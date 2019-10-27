# go-socks5

目前只支持转发TCP流量

### 如何使用

`./proxy1 [Deprecated]`

相关文件:

* 客户端配置文件名为 `./proxy2/client.json`

* 服务端配置文件名为 `./proxy2/server.json`

* 入口文件 `proxy2/proxy.go` 

保证两者配置文件关键参数一致, 启动顺序如下:

1. 启动服务端 `go run ./proxy2/proxy.go -server -config .`

2. 启动客户端 `go run ./proxy2/proxy.go -config .`

```json
{
    "http_server": ":9000",
    "proxy_mode": 1,
    "proxy_server": "127.0.0.1:8080",
    "server_pprof_port": "0.0.0.0:10001",
    "client_pprof_port": "0.0.0.0:10002",
    "proxy_router": [
        {
            "in": ":8888",
            "out": ":8090"
        },
        {
            "in": ":10101",
            "out": ":9900"
        }
    ],
    "socks5": {
        "verison": 5,
        "username": "hi",
        "password": "zerpro"
    },
    "kcp": {
        "key": "hizerpro",
        "salt": "hahahahahahaha",
        "crypt": "aes",
        "mode": "fast3",
        "mtu": 1400,
        "sndwnd": 128,
        "rcvwnd": 1024,
        "datashard": 10,
        "parityshard": 3,
        "dscp": 46,
        "acknodelay": false,
        "nodelay": 1,
        "interval": 40,
        "resend": 2,
        "nc": 1,
        "sockbuf": 20480,
        "pinginterval": 5,
        "pongtimeout": 5
    },
    "smux": {
        "version": 2,
        "keep_alive_interval": 12,
        "keep_alive_timeout": 24,
        "max_frame_size": 128,
        "max_stream_buffer": 1024
    }
}
```

### 参数解释

* http_server: 预留的http api接口

* proxy_mode:

> 多条TCP链接分享同一个远程端口
>
> proxyMode=0:
>
> 1. [内网]client -> proxy -> [公网]target
>
> 2. [公网]target -> proxy -> [内网]client
>
> 3. Done.
>
> proxyMode=1:
>
> 1. [内网]client -> proxy -> [公网]target
>
> 2. Done.

* proxy_router:

> ​	 => {localAddr : targetAddr}
>
> ​	localAddr 代理流量入口地址
>
> ​	targetAddr 代理流量出口地址 由代理服务器来发起连接

* socks5参数 目前只支持无认证和用户名密码认证, 只支持connect指令

* 所有kcp,smux参数都有默认值, 在json配置文件中可选设置, 也可删除项即使用默认值.