kcptun-raw
----------
为缓解部分ISP对UDP断流的问题，通过伪造TCP报文，实现了[kcptun](https://github.com/xtaci/kcptun)的最基本功能。目前只实现了最基本的明文tunnel。  
客户端到服务端的底层通信方式为带伪TCP报头的IP packet，通过raw socket实现。

Inspired by [linhua55/some_kcptun_tools/relayRawSocket](https://github.com/linhua55/some_kcptun_tools/tree/master/relayRawSocket) .

Usage
-----
编译依赖：`libev-devel`
```
$ make
```
假设服务器IP为108.8.8.1，80端口上有web服务，伪TCP头的端口为888；  
本地机器IP为192.168.1.100（通常是路由器分配的IP，不能使用127.0.0.1），TCP监听端口为9999。

服务端：
```
# iptables -A INPUT -p tcp --dport 888 -j DROP
# ./server 127.0.0.1 80 108.8.8.1 888 fast2
```

客户端：
```
# iptables -A INPUT -p tcp -s 108.8.8.1 --sport 888 -j DROP
# ./client 108.8.8.1 888 192.168.1.100 9999 fast2
$ curl localhost:9999
```
