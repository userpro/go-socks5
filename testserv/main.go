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
	buff := make([]byte, 1024)
	for {
		c.SetReadDeadline(time.Now().Add(time.Second * 3))
		if _, err := c.Read(buff); err != nil {
			log.Println(err)
			return
		}
		log.Println("server recv: ", string(buff))

		c.SetWriteDeadline(time.Now().Add(time.Second * 3))
		if _, err := c.Write([]byte("pong")); err != nil {
			log.Println(err)
			return
		}
	}
}
