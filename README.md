kcptun-raw
----------
为缓解部分ISP对UDP断流的问题，通过伪造TCP报文，实现了[kcptun](https://github.com/xtaci/kcptun)的基本功能。
客户端到服务端的底层通信方式为带伪TCP报头的IP packet，通过raw socket实现。

Inspired by [linhua55/some_kcptun_tools/relayRawSocket](https://github.com/linhua55/some_kcptun_tools/tree/master/relayRawSocket) .

Usage
-----
编译依赖：`libev-devel`, `openssl-devel`
```
$ make
```

```
# ./server TARGET_IP TARGET_PORT SERVER_IP SERVER_PORT [--key 16_BYTES_KEY] [--mode MODE] [--noseq]
# ./client SERVER_IP SERVER_PORT LOCAL_IP LISTEN_PORT [--key 16_BYTES_KEY] [--mode MODE] [--noseq]
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

如果客户端log中有大量`Re-init fake TCP connection`，请尝试在客户端和服务端的命令都添加`--noseq`参数。

可选参数说明：  
* `[--mode]` 加速模式，取值为`normal/fast/fast2/fast3`。默认为`fast3`。  
* `[--noseq]` 如果添加该参数，则取消伪TCP头的sequence自增，可避免部分ISP环境下的断流情况。  
* `[--key 16_BYTES_KEY]` AES128密钥，长度必须为16字节。默认为`it is a secrect!`。  

分层示意图
--------
![](./layers.png)
