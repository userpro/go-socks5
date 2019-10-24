package main

import (
	"io"
	"net"
	"socks5"
	"socks5/protocol"
	"time"

	log "github.com/sirupsen/logrus"
	smuxv2 "github.com/xtaci/smux/v2"
)

// 1. [内网]client -> proxy -> [公网]server
// 2. [公网]server -> proxy -> [内网]client

const (
	localAddr  = "127.0.0.1:8888"
	proxyAddr  = "127.0.0.1:8080"
	remoteAddr = "127.0.0.1:8090"
)

var (
	s5 = socks5.S5Protocol{
		Version:           5,
		Username:          "hi",
		Password:          "zerpro",
		AuthMethodSupport: []byte{socks5.AuthNoAuthRequired},
		DirectMode:        true,
	}
)

func main() {
	go server()
	time.Sleep(time.Second)
	client()
}

func muxClient(conn io.ReadWriteCloser) {
	log.Info("muxClient start")
	session, err := smuxv2.Client(conn, nil)
	if err != nil {
		log.Error("[muxClient] Client err: ", err)
		return
	}
	defer session.Close()

	proxyConn := func(dst io.ReadWriteCloser) {
		stream, err := session.OpenStream()
		if err != nil {
			log.Error("[muxClient] OpenStream err: ", err)
			return
		}

		defer stream.Close()
		if err := s5.Dial(stream); err != nil {
			log.Error("[muxClient] Dial err: ", err)
			return
		}

		if _, err := s5.Connect(stream, proxyAddr, remoteAddr); err != nil {
			log.Error("[muxClient] Connect err: ", err)
			return
		}

		// 发送真实流量
		socks5.ProxyStream(dst, stream)
	}

	// 在公网机器上开启本地端口转发
	if serv, err := net.Listen("tcp", localAddr); err == nil {
		defer serv.Close()
		for {
			servConn, err := serv.Accept()
			if err != nil {
				log.Error("[muxClient] Inner accept err: ", err)
				return
			}
			go proxyConn(servConn)
		}
	} else {
		log.Fatal("[muxClient] tcp server start err: ", err)
	}
}

func muxServer(conn io.ReadWriteCloser) {
	log.Info("muxServer start")
	smuxConfig := smuxv2.DefaultConfig()
	muxer, err := smuxv2.Server(conn, smuxConfig)
	if err != nil {
		log.Error("[muxServer] Server ", err)
		return
	}
	defer muxer.Close()

	for {
		stream, err := muxer.AcceptStream()
		if err != nil {
			log.Error("[muxServer] Accept ", err)
			return
		}

		go func() {
			defer log.Info("muxServer quit")
			defer stream.Close()

			s5.Server(stream)
		}()
	}
}

func server() {
	lis := protocol.New()
	if err := lis.Listen(proxyAddr); err == nil {
		defer lis.Close()
		conn, err := lis.Accept()
		if err != nil {
			log.Error("[server] Outside accept err: ", err)
			return
		}

		conn.SetReadTimeout(0)
		conn.SetWriteTimeout(0)
		time.Sleep(time.Second)
		muxClient(conn)
	}
}

func client() {
	conn := protocol.New()
	err := conn.Dial(proxyAddr)
	if err != nil {
		log.Error("[client] Dial err: ", err)
		return
	}
	defer conn.Close()
	conn.SetReadTimeout(0)
	conn.SetWriteTimeout(0)
	muxServer(conn)
}
