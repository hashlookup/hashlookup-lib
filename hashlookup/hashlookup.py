#!/usr/bin/env python
"""
Hashlookup is a library to import hashes records into a hashlookup server.

The library cleans up the format in the entry, do normalization such as upper-case of hex hashes,
verify meta-field definition and ensure consistency in the key/value store.

A hashlookup server is a Redis-compatible datastore.

"""

__author__ = "Alexandre Dulaunoy"
__copyright__ = "Copyright 2021, Alexandre Dulaunoy"
__license__ = "AGPL License"
__version__ = "1.2"

import redis
import time
import json


class HashLookupInsert:
    def __init__(
        self,
        update=True,
        skipexists=False,
        validate=True,
        publish=False,
        channel="hashlookup-insert",
        source=None,
        host="127.0.0.1",
        port=6666,
    ):
        self.update = update
        self.version = __version__
        self.parent = []
        self.parent_meta = {}
        self.children = []
        self.record = {}
        self.publish = publish
        self.channel = channel
        self.skipexists = skipexists
        self.source = source
        if source is not None:
            self.record["source"] = self.source
        self.rdb = redis.Redis(host=host, port=port, decode_responses=True)
        self.known_hashtypes = ["SHA-1", "MD5", "SHA-256", "SHA-512", "TLSH", "SSDEEP"]
        self.known_meta = [
            "FileName",
            "FileSize",
            "CRC",
            "CRC32",
            "SpecialCode",
            "OpSystemCode",
            "ProductCode",
            "PackageName",
            "PackageMaintainer",
            "PackageSection",
            "PackageVersion",
            "KnownMalicious",
            "source",
            "db",
            "mimetype",
            "tar:gname",
            "tar:uname",
            "nsrl-sha256",
            "insert-timestamp"
        ]

    def cleanup(self):
        """Cleanup the record after this has been inserted in the hashlookup store."""
        self.parent = []
        self.children = []
        self.record = {}
        if self.source is not None:
            self.record["source"] = self.source

    def is_hex(self, s):
        """Check if the string is expressed in hexadecimal."""
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def check_md5(self, value=None):
        """Check if the value match a hexadecimal representation of an MD5 hash."""
        if value is None or len(value) != 32:
            return False
        if not self.is_hex(value):
            return False
        k = value.upper()
        return k

    def check_sha1(self, value=None):
        """Check if the value match a hexadecimal representation of an SHA1 hash."""
        if value is None or len(value) != 40:
            return False
        if not self.is_hex(value):
            return False
        k = value.upper()
        return k

    def add_hash(self, value=None, hashtype=None):
        """Add a hexadecimal representation of hash."""
        if value is None or hashtype is None:
            return False
        hashtype = hashtype.upper()
        if not (hashtype in self.known_hashtypes):
            return False
        if hashtype in ["SHA-1", "MD5", "SHA-256"]:
            value = value.upper()
        self.record[hashtype] = value

    def add_meta(self, key=None, value=None, validate=True):
        """Add a meta field to the record. The field name is checked against the list of known meta fields."""
        if key is None or value is None:
            return False
        if not (key in self.known_meta):
            return False
        self.record[key] = value

    def add_parent(self, value=None):
        """Add a parent (in SHA-1 hexadecimal representation) to the current record."""
        h = self.check_sha1(value=value)
        if h:
            self.parent.append(h)
        else:
            return False

    def add_parent_meta(self, value=None, meta_key=None, meta_value=None):
        """Add a parent meta to the current record. It will the parent record with the associated meta fields."""
        h = self.check_sha1(value=value)
        if meta_key is None or meta_value is None or value is None:
            return False
        if h not in self.parent_meta:
            self.parent_meta[h] = []
        self.parent_meta[h].append({meta_key: meta_value})

    def add_children(self, value=None):
        """Add a child (in SHA-1 hexadecimal representation to the current record."""
        h = self.check_sha1(value=value)
        if h:
            self.children.append(h)
        else:
            return False

    def get_version(self):
        """Get current version of the hashlookup library."""
        return self.version

    def insert(self):
        """Insert the record in the hashlookup store. The associated structures are updated according the hashlookup data-structure backend."""
        self.none = ""
        self.record["insert-timestamp"] = time.time()
        if self.skipexists:
            if self.rdb.exists("h:{}".format(self.record["SHA-1"])):
                self.cleanup()
                return False
        if not "SHA-1" in self.record:
            return False
        if not self.update:
            if "MD5" in self.record:
                self.rdb.delete("l:{}".format(self.record["MD5"]))
            self.rdb.delete("h:{}".format(self.record["SHA-1"]))
            if "SHA-256" in self.record:
                self.rdb.delete("l:{}".format(self.record["SHA-256"]))
            if "TLSH" in self.record:
                self.rdb.delete("l:{}".format(self.record["TLSH"]))
            if "SSDEEP" in self.record:
                self.rdb.delete("l:{}".format(self.record["SSDEEP"]))
        if "MD5" in self.record:
            self.rdb.set("l:{}".format(self.record["MD5"]), self.record["SHA-1"])
        if "SHA-256" in self.record:
            self.rdb.set("l:{}".format(self.record["SHA-256"]), self.record["SHA-1"])
        if "TLSH" in self.record:
            self.rdb.set("l:{}".format(self.record["TLSH"]), self.record["SHA-1"])
        if "SSDEEP" in self.record:
            self.rdb.set("l:{}".format(self.record["SSDEEP"]), self.record["SHA-1"])
        self.rdb.hmset("h:{}".format(self.record["SHA-1"]), self.record)
        for parent in self.parent:
            self.rdb.sadd("p:{}".format(self.record["SHA-1"]), parent)
            self.rdb.sadd("c:{}".format(parent), self.record["SHA-1"])
            if not self.rdb.exists("h:{}".format(parent)):
                self.rdb.hset("h:{}".format(parent), key="SHA-1", value=parent)
        for key in self.parent_meta:
            for k in self.parent_meta[key]:
                for kparent in k.keys():
                    if not self.rdb.hexists("h:{}".format(key), kparent):
                        self.rdb.hset("h:{}".format(key), key=kparent, value=k[kparent])
        for child in self.children:
            self.rdb.sadd("c:{}".format(child), self.record["SHA-1"])
            self.rdb.sadd("p:{}".format(self.record["SHA-1"]), child)
            if not self.rdb.exists("h:{}".format(child)):
                self.rdb.hset("h:{}".format(child), key="SHA-1", value=child)
        if 'mimetype' in self.record:
            self.rdb.sadd("m:{}".format(self.record["mimetype"]), self.record['SHA-1'])
        if self.publish:
            self.rdb.publish(self.channel, json.dumps(self.record))
        r = self.record
        self.cleanup()
        return(r)


if __name__ == "__main__":
    h = HashLookupInsert(update=True, source="lib-test", publish=True)
    v = h.get_version()
    print(f"Version used:{v}")
    h.add_hash()
    h.add_hash(value="e7793f15c2ff7e747b4bc7079f5cd4f7", hashtype="Md5")
    h.add_hash(value="732458574c63c3790cad093a36eadfb990d11ee6", hashtype="sha-1")
    h.add_meta(key="FileName", value="/bin/ls")
    h.add_children(value="d0235872b0f5d50cd9ce789690249fac3ceb9045")
    h.insert()
    h.add_hash(value="e7793f15c2ff7e747b4bc7079f5cd4f7", hashtype="Md5")
    h.add_hash(
        value="1e39354a6e481dac48375bfebb126fd96aed4e23bab3c53ed6ecf1c5e4d5736d",
        hashtype="SHa-256",
    )
    h.add_hash(value="732458574c63c3790cad093a36eadfb990d11ee6", hashtype="sha-1")
    h.insert()
    h = HashLookupInsert(update=True, source="lib-test", publish=True, skipexists=False)
    h.add_hash(value="732458574c63c3790cad093a36eadfb990d11ee6", hashtype="sha-1")
    h.add_hash(value="1536:TqAwq5L4YLfAbFlIDgCicFoYq26JNM7ML02H4SFlv6Hm:TaQ4Yxjq5dYSFlv", hashtype="ssdeep")
    h.add_parent(value="d0235872b0f5d50cd9ce789690249fac3ceb9045")
    h.add_parent_meta(value="d0235872b0f5d50cd9ce789690249fac3ceb9045", meta_key="original-filename", meta_value="foobar")
    h.add_parent_meta(value="d0235872b0f5d50cd9ce789690249fac3ceb9045", meta_key="bar", meta_value="foo")
    h.insert()
