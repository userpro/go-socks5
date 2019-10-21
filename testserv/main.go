package main

import (
	"log"
	"net"
	"time"
)

func main() {
	var conn net.Listener
	var err error
	if conn, err = net.Listen("tcp", ":8090"); err != nil {
		log.Println(err)
	}
	for {
		c, err := conn.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("get connect ", c.RemoteAddr().String())
		go handle(c)
	}
}

func handle(c net.Conn) {
	buff := make([]byte, 128)
	var totalrecv int
	var nread int
	var err error
	for {
		c.SetReadDeadline(time.Now().Add(time.Second * 3))
		if nread, err = c.Read(buff); err != nil {
			log.Println(err)
			break
		}
		totalrecv += nread
		// log.Println("server recv: ", buff[:nread])

		c.SetWriteDeadline(time.Now().Add(time.Second * 3))
		if _, err = c.Write(buff[:nread]); err != nil {
			log.Println(err)
			break
		}
	}
	log.Println("total recv: ", totalrecv)
}
