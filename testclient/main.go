package main

import (
	"log"
	"net"
	"time"
)

func main() {
	var conn net.Conn
	var err error

	if conn, err = net.Dial("tcp", ":8888"); err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	log.Println("client dial ok")

	buff := make([]byte, 1024)
	for {
		conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
		if _, err := conn.Write([]byte("ping")); err != nil {
			log.Println(err)
			return
		}

		conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		if _, err := conn.Read(buff); err != nil {
			log.Println(err)
			return
		}
		log.Println("client recv ", string(buff))
		time.Sleep(time.Second)
		// return
	}
}
