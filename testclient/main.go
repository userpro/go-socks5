package main

import (
	"log"
	"net"
	"time"
)

func main() {
	var conn net.Conn
	var err error

	if conn, err = net.Dial("tcp", "47.100.181.160:54488"); err != nil {
		log.Println(err)
		return
	}
	log.Println("dial ok")
	conn.SetDeadline(time.Now().Add(time.Second * 3))
	buff := make([]byte, 1024)
	for {
		if _, err := conn.Write([]byte("ping")); err != nil {
			log.Println(err)
			return
		}
		log.Println("write ok")

		if _, err := conn.Read(buff); err != nil {
			log.Println(err)
			return
		}
		log.Println(string(buff))
		time.Sleep(time.Second)
	}
}
