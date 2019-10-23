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

const (
	localAddr  = "127.0.0.1:8888"
	proxyAddr  = "127.0.0.1:8080"
	remoteAddr = "127.0.0.1:8090"
)

func client() {
	log.Info("client start")
	conn := protocol.New()
	if err := conn.Dial(proxyAddr); err != nil {
		log.Error("[client] Dial ", err)
		return
	}
	defer conn.Close()

	muxServer(conn)
}

func server() {
	log.Info("server start")
	lis := protocol.New()
	if err := lis.Listen(proxyAddr); err != nil {
		log.Error("[server] Listen ", err)
		return
	}
	defer lis.Close()

	conn, err := lis.Accept()
	if err != nil {
		log.Error("[server] Accept ", err)
		return
	}

	muxClient(conn)
}

func muxClient(conn protocol.Conn) {
	log.Info("muxClient start")
	lis, err := net.Listen("tcp", remoteAddr)
	if err != nil {
		log.Error("[muxClient] Listen ", err)
		return
	}

	for {
		local, err := lis.Accept()
		if err != nil {
			log.Error("[muxClient] Accept ", err)
			return
		}
		handleClientConn(conn, local)
	}
}

// 代理客户端数据
func handleClientConn(conn protocol.Conn, local net.Conn) {
	defer local.Close()
	session, err := smuxv2.Client(conn, nil)
	if err != nil {
		log.Error("[handleClientConn] Client ", err)
		return
	}
	defer session.Close()

	stream, err := session.OpenStream()
	if err != nil {
		log.Error("[handleClientConn] OpenStream ", err)
		return
	}
	defer stream.Close()

	s5 := socks5.NewS5Protocol()
	if err := s5.Dial(stream); err != nil {
		log.Error("[handleClientConn] Dial ", err)
		return
	}
	log.Info("socks5 handshake ok.")

	if _, err := s5.Connect(stream, proxyAddr, remoteAddr); err != nil {
		log.Error("[handleClientConn] Connect ", err)
		return
	}

	socks5.ProxyStream(stream, local)
}

func muxServer(conn protocol.Conn) {
	log.Info("muxServer start")
	smuxConfig := smuxv2.DefaultConfig()
	muxer, err := smuxv2.Server(conn, smuxConfig)
	if err != nil {
		log.Error("[muxServer] Server ", err)
		return
	}
	defer muxer.Close()

	for {
		stream, err := muxer.Accept() // TODO Timeout
		if err != nil {
			log.Error("[muxServer] Accept ", err)
			return
		}

		go handleServConn(stream)
	}
}

// 代理服务端数据
func handleServConn(conn io.ReadWriteCloser) {
	defer conn.Close()
	s5 := socks5.NewS5Protocol()
	s5.SetDirectMode(true)
	s5.Server(conn)
}

func main() {
	go server()
	time.Sleep(time.Second * 2)
	client()
}
