package main

import (
	"socks5"
	"socks5/protocol"

	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"

	log "github.com/sirupsen/logrus"
	smuxv2 "github.com/xtaci/smux/v2"
)

/*
	1. [内网]client -> proxy -> [公网]target
	2. [公网]target -> proxy -> [内网]client
	3. Done.
	多条TCP链接分享同一个远程端口
*/

const (
	httpServer  = ":9000"
	proxyServer = "127.0.0.1:8080"
)

var (
	// ProxyRouter => {localAddr : targetAddr}
	// localAddr 代理流量入口地址
	// targetAddr 代理流量出口地址 由代理服务器来发起连接
	ProxyRouter = map[string]string{
		":8888": ":8090",
	}

	s5 = socks5.S5Protocol{
		Version:           5,
		Username:          "hi",
		Password:          "zerpro",
		AuthMethodSupport: []byte{socks5.AuthNoAuthRequired},
		DirectMode:        true,
		ConnConfig: &protocol.KcpConfig{
			Key:  "wdnmd",
			Salt: "hahahahahahah",
		},
	}
)

func main() {
	go server()
	time.Sleep(time.Second)
	go client()
	log.Fatal(http.ListenAndServe(":9999", nil)) // pprof
}

func muxClient(conn io.ReadWriteCloser) {
	log.Info("muxClient start")
	buff := make([]byte, 1)
	if _, err := conn.Read(buff); err != nil {
		log.Error("[muxClient] ping recv err: ", err)
		return
	}
	session, err := smuxv2.Client(conn, nil)
	if err != nil {
		log.Error("[muxClient] Client err: ", err)
		return
	}
	defer session.Close()

	proxyConn := func(dst io.ReadWriteCloser, remoteAddr string) {
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

		if _, err := s5.Connect(stream, proxyServer, remoteAddr); err != nil {
			log.Error("[muxClient] Connect err: ", err)
			return
		}

		// 发送真实流量
		socks5.ProxyStream(dst, stream)
	}

	// 在公网机器上开启本地端口转发
	for localAddr, remoteAddr := range ProxyRouter {
		go func(localAddr, remoteAddr string) {
			if serv, err := net.Listen("tcp", localAddr); err == nil {
				defer serv.Close()
				for {
					servConn, err := serv.Accept()
					if err != nil {
						log.Error("[muxClient] Inner accept err: ", err)
						return
					}
					go proxyConn(servConn, remoteAddr)
				}
			} else {
				log.Fatal("[muxClient] tcp server start err: ", err)
			}
		}(localAddr, remoteAddr)
	}

	// TODO: HTTP API 动态修改路由
	log.Fatal(http.ListenAndServe(httpServer, nil))
}

func muxServer(conn io.ReadWriteCloser) {
	log.Info("muxServer start")
	if _, err := conn.Write([]byte{byte(0x01)}); err != nil {
		log.Error("[muxServer] ping err: ", err)
		return
	}
	smuxConfig := smuxv2.DefaultConfig()
	muxer, err := smuxv2.Server(conn, smuxConfig)
	if err != nil {
		log.Error("[muxServer] Server ", err)
		return
	}
	defer muxer.Close()

	// 接收代理链接
	for {
		stream, err := muxer.AcceptStream()
		if err != nil {
			log.Error("[muxServer] Accept ", err)
			return
		}

		go func() {
			defer log.Info("s5 connect quit")
			defer stream.Close()

			// 根据socks5协议 代理流量
			s5.Server(stream)
		}()
	}
}

func server() {
	lis := protocol.New(&protocol.KcpConfig{})
	if err := lis.Listen(proxyServer); err == nil {
		defer lis.Close()
		conn, err := lis.Accept()
		if err != nil {
			log.Error("[server] Outside accept err: ", err)
			return
		}
		conn.SetReadTimeout(0)
		conn.SetWriteTimeout(0)
		muxClient(conn)
	}
}

func client() {
	conn := protocol.New()
	err := conn.Dial(proxyServer)
	if err != nil {
		log.Error("[client] Dial err: ", err)
		return
	}
	defer conn.Close()
	conn.SetReadTimeout(0)
	conn.SetWriteTimeout(0)
	muxServer(conn)
}
