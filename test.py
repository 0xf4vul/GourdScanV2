# !/usr/bin/env python
#  -*- coding: utf-8 -*-
import pymongo
import datetime

client = pymongo.MongoClient('mongodb://exp.cdxy.me:27015/')
db = client.test_database
collection = db.test_collection
port = {"author": "mike", "date": "1"}
ports = db.ports
port_id = ports.insert(port)
