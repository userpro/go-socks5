package main

import (
	"log"
	"net"
)

func main() {
	var conn net.Listener
	var err error
	if conn, err = net.Listen("tcp", "127.0.0.1:8090"); err != nil {
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
		if _, err := c.Read(buff); err != nil {
			log.Println(err)
			return
		}
		log.Println(string(buff))

		if _, err := c.Write([]byte("pong")); err != nil {
			log.Println(err)
			return
		}
	}
}
