dhcp6d
======

Command `dhcp6d` is an example DHCPv6 server.  It can only assign a
single IPv6 address, and is not a complete DHCPv6 server implementation
by any means.  It is meant to demonstrate usage of package `dhcp6`.

Example
-------

This example makes use of two machines (a client, "dhcp6c", and server,
"dhcp6d") and the `dhclient(8)` and `dhcp6d` binaries.

Use server to begin serving a single IPv6 address using DHCPv6:

```
matt@dhcp6d:~$ sudo ./dhcp6d -h
Usage of ./dhcp6d:
  -i string
        interface to serve DHCPv6 (default "eth0")
  -ip string
        IPv6 address to serve over DHCPv6
matt@dhcp6d:~$ sudo ./dhcp6d -i eth0 -ip dead:beef:d34d:b33f::10
2015/09/02 14:50:31 binding DHCPv6 server to interface eth0...
```

Use client to request an IPv6 address using DHCPv6:

```
matt@dhcp6c:~$ ifconfig eth0 | grep ::10
matt@dhcp6c:~$ sudo dhclient -6 eth0
matt@dhcp6c:~$ ifconfig eth0 | grep ::10
          inet6 addr: dead:beef:d34d:b33f::10/64 Scope:Global
```
