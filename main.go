package main

import (
	"socks5"

	"time"

	log "github.com/sirupsen/logrus"
)

func client() {
	log.Info("proxy client start")
	// proxyRouter => {localAddress : dstAddress}
	// localAddress 代理流量入口地址 (客户端视角)
	// dstAddress 代理流量出口地址 由代理服务器来发起连接 (代理服务器视角)
	proxyRouter := map[string]string{
		":8888": ":8090",
	}
	pc := &socks5.ProxyClient{
		HTTPServer:  ":9000",
		ProxyServer: "127.0.0.1:8080",
		ProxyRouter: proxyRouter,
		Opts: &socks5.ClientOpts{
			Username:     "hi",
			Password:     "zerpro",
			ReadTimeout:  time.Second * 5,
			WriteTimeout: time.Second * 5,
		},
	}
	pc.Proxy()
}

func server() {
	log.Info("server start")
	s := socks5.NewServerWithTimeout(&socks5.ServerOpts{
		Username:     "hi",
		Password:     "zerpro",
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
	})
	if err := s.Listen(":8080"); err != nil {
		log.Error(err)
	}
}

func main() {
	go server()
	time.Sleep(time.Second * 2)
	client()
}
