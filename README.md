# Welcome to hashlookup-lib

Hashlookup is a library to import hashes records into a hashlookup server.

The library cleans up the format in the entry, do normalization such as upper-case of hex hashes, verify meta-field definition and ensure consistency in the key/value store.

A hashlookup server is a Redis-compatible datastore.

# Installation

`pip3 install .`

## Usage

~~~~python
h = HashLookupInsert(update=True, source="lib-test", publish=True)
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
h.add_parent(value="d0235872b0f5d50cd9ce789690249fac3ceb9045")
h.add_parent_meta(value="d0235872b0f5d50cd9ce789690249fac3ceb9045", meta_key="original-filename", meta_value="foobar")
h.add_parent_meta(value="d0235872b0f5d50cd9ce789690249fac3ceb9045", meta_key="bar", meta_value="foo")
h.insert()
~~~~

## Documentation

Documentation of the API is [available](https://hashlookup.github.io/hashlookup-lib/hashlookup/hashlookup.html).
