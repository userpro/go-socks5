package main

import (
	"log"
	"net"
	"time"

	"github.com/segmentio/ksuid"
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

	ks := ksuid.New()
	sid := ks.Bytes()
	log.Println(ks.String())

	buff := make([]byte, 128)
	var totalread int
	var nread int
	for {
		conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
		if _, err = conn.Write(sid); err != nil {
			log.Println(err)
			break
		}

		conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		if nread, err = conn.Read(buff); err != nil {
			log.Println(err)
			break
		}
		totalread += nread
		// log.Println("client recv ", buff[:nread])
		time.Sleep(time.Millisecond * 100)
		// return
	}
	log.Println("total recv: ", totalread)
}
