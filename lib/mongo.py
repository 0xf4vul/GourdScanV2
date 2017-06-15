# !/usr/bin/env python
#  -*- coding: utf-8 -*-
import pymongo
import urlparse
from hashlib import md5
from enums import *
from lib.settings import CHECK_CONF_FILE
from lib import config

client = pymongo.MongoClient('mongodb://localhost:27015/')  # TODO move this to config.json
db = client.gdscan
conn = db.gdscan_reqs


# TODO 若使用hash来去重，需要改进此函数
def get_hash(host, uri, postdata):
    """
    根据每个请求内容生成hash
    """
    request = 'http://%s%s?' % (host, urlparse.urlparse(uri).path)
    dic = urlparse.urlparse(uri).query.split('&')
    for param in dic:
        if param != "" and "=" in param:
            request += param.split('=')[0] + '=&'
    request += "|"
    for param in postdata.split('&'):
        if param != "" and "=" in param:
            request += param.split('=')[0] + '=&'
    url_hash = md5(request).hexdigest()
    return url_hash


def mongo_insert(headers, host, method, postdata, uri, packet):
    """
    向数据库中写入新任务
    """
    u = urlparse.urlparse(uri)
    url = uri.split(u.netloc)[-1]  # TODO ???
    white_domain = config.load()['white_domain']
    black_domain = config.load()['black_domain']
    black_ext = config.load()['black_ext']
    for ext in black_ext.split(','):
        if u.path.lower().endswith("." + ext):
            return
    for domain in black_domain.split(','):
        if u.netloc.lower().split(':')[0].endswith(domain):
            return
    if white_domain != "":
        for domain in white_domain.split(','):
            if not u.netloc.lower().split(':')[0].endswith(domain):
                return
    reqhash = get_hash(host, uri, postdata)

    # 用hash去重
    if 'Gdscan' in headers.keys() or ReqItem.hash_exists(reqhash):
        return
    else:
        # 表结构
        new_item = {
            'hash': reqhash,
            'request': {
                'headers': headers,
                'host': host,
                'method': method,
                'postdata': postdata,
                'url': uri,
                'packet': packet
            },
            'response': {},
            'status': ITEM_STATUS.WAITING,
            'vulnerable': 0
        }
        conn.insert(new_item)


class ReqItem:
    """
    封装gdscan_reqs表中所有的数据库操作
    """

    def __init__(self, hash=None):
        """ init
        :param hash: 以hash检索数据库并取出对应任务，若为空则取出一个新的waiting任务
        """
        if hash:
            self.hash = hash
            self.data_obj = conn.find_one({'hash': hash})
        else:
            self.data_obj = conn.find_one({'status': ITEM_STATUS.WAITING})
            self.hash = self.data_obj['hash']

    def set_status(self, status):
        """
        设定任务状态
        :param status: ITEM_STATUS.WAITING/RUNNING/FINISHED
        """
        conn.update({"_id": self.data_obj['_id']}, {"$set": {"status": status}})

    def set_result(self, result):
        """
        设定response数据
        :param result: dict(result_obj)
        """
        conn.update({"_id": self.data_obj['_id']}, {"$set": {"response": result}})

    def mark_vulnerable(self):
        """
        标记为检出漏洞
        """
        conn.update({"_id": self.data_obj['_id']}, {"$set": {"vulnerable": 1}})

    @staticmethod
    def status_count(status):
        """
        获取指定状态的任务数量
        :param status: ITEM_STATUS.WAITING/RUNNING/FINISHED
        :return: count
        """
        return conn.find({"status": status}).count()

    @staticmethod
    def vulnerable_count():
        """
        获取vulnerable=1的任务数量
        :return: count
        """
        return conn.find({"vulnerable": 1}).count()

    @staticmethod
    def hash_exists(hash):
        """
        检查指定hash是否存在
        :return: True / False
        """
        return bool(conn.find({"hash": hash}).count())

    @staticmethod
    def delete(status=None):
        """
        根据给定条件删除数据
        :param status: ITEM_STATUS.WAITING/RUNNING/FINISHED
        """
        if status:
            return conn.remove({"status": status})
        else:
            return conn.remove()
