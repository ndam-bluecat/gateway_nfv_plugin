# Memcached NFV-PLUGIN
## Start memcached server
```ruby
docker run -p 11211:11211 --name nfv-memcache -d memcached memcached -m 10
```
*10: Memcached server to use 10 megabytes for storage.
## Usage
```
from memcached.memcached_nfv import MemcachedNFV
from memcached.server import ServerType

mem_nfv = MemcachedNFV(HOST, PORT)

# BDDS
mem_nfv.set_server(list_server[0], ServerType.BDDS, "192.168.88.54")
# BAM
mem_nfv.set_server({'ipv4_address': '192.168.88.248'}, ServerType.BAM)

mem_nfv.disconnect()
```