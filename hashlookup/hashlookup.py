#!/usr/bin/env python
"""
Hashlookup is a library to import hashes records into hashlookup server.
"""

__author__ = "Alexandre Dulaunoy"
__copyright__ = "Copyright 2021, Alexandre Dulaunoy"
__license__ = "MIT License"
__version__ = "0.9"

import redis
import time

class HashLookupInsert:
    def __init__(self, update=True, validate=True, PubSubInsert=False, host='127.0.0.1', port=6666):
        self.update = update
        self.parent = []
        self.children = []
        self.record = {}
        self.rdb = redis.Redis(host=host, port=port, decode_responses=True)
        self.known_hashtypes = ['SHA-1', 'MD5', 'SHA-256', 'TLSH', 'SSDEEP']
        self.known_meta = ['FileName', 'FileSize', 'CRC', 'SpecialCode', 'OpSystemCode', 'ProductCode', 'PackageName', 'PackageMaintainer', 'PackageSection', 'PackageVersion', 'KnownMalicious', 'source', 'db']

    def cleanup(self):
        self.parent = []
        self.children = []
        self.record = {}
    
    def is_hex(self, s):
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def check_md5(self, value=None):
        if value is None or len(value) != 32:
            return False
        if not self.is_hex(value):
            return False
        k = value.upper()
        return k

    def check_sha1(self, value=None):
        if value is None or len(value) != 40:
            return False
        if not self.is_hex(value):
            return False
        k = value.upper()
        return k

    def add_hash(self, value=None, hashtype=None):
        if value is None or hashtype is None:
            return False
        hashtype = hashtype.upper()
        if not(hashtype in self.known_hashtypes):
            return False
        self.record[hashtype] = value 

    def add_meta(self, key=None, value=None, validate=True):
        if key is None or value is None:
            return False
        if not(key in self.known_meta):
            return False
        self.record[key] = value

    def add_parent(self, value=None):
        h = self.check_sha1(value=value)
        if h:
            self.parent.append(h)
        else:
            return False

    def add_children(self, value=None):
        h = self.check_sha1(value=value)
        if h:
            self.children.append(value)
        else:
            return False

    def insert(self):
        self.none = '' 
        self.record['insert-timestamp'] = time.time()
        if not 'SHA-1' in self.record:
            return False
        if not self.update:
            self.rdb.delete("l:{}".format(self.record['MD5']))
            self.rdb.delete("h:{}".format(self.record['SHA-1']))
            if 'SHA-256' in self.record:
                self.rdb.delete("l:{}".format(self.record['SHA-256']))
        self.rdb.set("l:{}".format(self.record['MD5']), self.record['SHA-1'])
        if 'SHA-256' in self.record:
            self.rdb.set("l:{}".format(self.record['SHA-256']), self.record['SHA-1'])
        self.rdb.hmset("h:{}".format(self.record['SHA-1']), self.record)
        for parent in self.parent:
            self.rdb.sadd("p:{}".format(self.record['SHA-1']), parent)
        for child in self.children:
            self.rdb.sadd("c:{}".format(child), self.record['SHA-1'])
        print(self.record)
        self.cleanup()



        
if __name__ == "__main__":
    h = HashLookupInsert(update=False)
    h.add_hash()
    h.add_hash(value='e7793f15c2ff7e747b4bc7079f5cd4f7', hashtype='Md5')
    h.add_hash(value='732458574c63c3790cad093a36eadfb990d11ee6', hashtype='sha-1')
    h.add_meta(key='FileName', value='/bin/ls')
    h.add_children(value='d0235872b0f5d50cd9ce789690249fac3ceb9045')
    h.insert()
    