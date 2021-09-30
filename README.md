# Welcome to hashlookup-lib

# Installation

`pip3 install .`

## Usage

~~~~python

import hashlookup.hashlookup as hashlookup

h = hashlookup.HashLookupInsert(update=False)
h.add_hash()
h.add_hash(value='e7793f15c2ff7e747b4bc7079f5cd4f7', hashtype='Md5')
h.add_hash(value='732458574c63c3790cad093a36eadfb990d11ee6', hashtype='sha-1')
h.add_meta(key='FileName', value='/bin/ls')
h.add_children(value='d0235872b0f5d50cd9ce789690249fac3ceb9045')
h.insert()
~~~~

