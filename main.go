package main

import (
	"socks5"

	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func client() {
	c := socks5.NewClient(5, nil, "", "")
	if err := c.Dial("127.0.0.1", "8080"); err != nil {
		log.Error("Dial failed")
		os.Exit(1)
	}
	log.Info("socks5 handshake ok")
	// socks5.CmdConnect	socks5.CmdBind	socks5.CmdUDP
	// socks5.AddrDomain	socks5.AddrIPv4	socks5.AddrIPv6
	conn, err := c.Connect("127.0.0.1", "8090", socks5.CmdConnect)
	if err != nil {
		log.Error(err)
		return
	}
	defer conn.Close()

	log.Info("connect ok")
	buff := make([]byte, 1024)
	for {

		if _, err := conn.Write([]byte("ping")); err != nil {
			log.Error(err)
			return
		}

		if _, err := conn.Read(buff); err != nil {
			log.Error(err)
			return
		}
		log.Info(string(buff))

		time.Sleep(time.Second)
	}
}

func server() {
	// MUST timeout > 500ms
	s := socks5.NewServer(5, "", "", time.Second*4)
	if err := s.Listen("127.0.0.1", "8080"); err != nil {
		log.Error(err)
	}
}

func main() {
	go server()
	for {
		time.Sleep(time.Second * 3)
		client()
	}
}
