package main

import (
	"socks5"

	"time"

	log "github.com/sirupsen/logrus"
)

func client() {
	log.Info("proxy client start")
	proxyRouter := map[string]string{
		":8888": ":8090",
	}
	pc := &socks5.ProxyClient{}
	pc.Proxy("0.0.0.0:8080", proxyRouter, &socks5.ClientOpts{
		Username:     "hi",
		Password:     "zerpro",
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
	})
}

func server() {
	log.Info("server start")
	// MUST timeout > 500ms
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
