package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	log.Println(getExternalIP())
	var conn net.Conn
	var err error

	if conn, err = net.Dial("tcp", ":2321"); err != nil {
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

func getExternalIP() (ip string) {
	client := http.Client{
		Timeout: time.Second * 3,
	}
	resp, err := client.Get("http://myexternalip.com/raw")
	if err != nil {
		log.Println("[server.getExternalIP]", err)
		return
	}
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	return string(content)
}
