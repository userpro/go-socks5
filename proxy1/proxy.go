package main

import (
	"flag"
	"socks5"

	"net/http"
	_ "net/http/pprof"
	"time"

	log "github.com/sirupsen/logrus"
)

/*
	[内网]client -> proxy -> [公网]target
	一条TCP链接独占一个远程端口
*/

const (
	httpServer      = ":9000"
	proxyServer     = "127.0.0.1:8080"
	serverPprofPort = "10001"
	clientPprofPort = "10002"
)

var (
	isServer = flag.Bool("server", false, "true: server, false: client")

	// proxyRouter => {localAddr : targetAddr}
	// localAddr 代理流量入口地址
	// targetAddr 代理流量出口地址 由代理服务器来发起连接
	proxyRouter = map[string]string{
		":8888":  ":8090",
		":10101": ":9900",
	}

	clientOpts = &socks5.ClientOpts{
		Username:     "hi",
		Password:     "zerpro",
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
	}

	serverOpts = &socks5.ServerOpts{
		Username:     "hi",
		Password:     "zerpro",
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
	}
)

func client() {
	log.Info("proxy client start")
	pc := &ProxyClient{
		HTTPServer:  httpServer,
		ProxyServer: proxyServer,
		ProxyRouter: proxyRouter,
		Opts:        clientOpts,
	}
	pc.Proxy()
}

func server() {
	log.Info("server start")
	s := socks5.NewServerWithOpts(serverOpts)
	if err := s.Listen(proxyServer); err != nil {
		log.Error(err)
	}
}

func main() {
	flag.Parse()
	var pprofPort string
	if *isServer {
		go server()
		pprofPort = serverPprofPort
		// TODO: HTTP API 动态修改路由
		// log.Fatal(http.ListenAndServe(httpServer, nil))
	} else {
		go client()
		pprofPort = clientPprofPort
	}
	log.Fatal(http.ListenAndServe("0.0.0.0:"+pprofPort, nil)) // pprof
}
