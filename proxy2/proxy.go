package main

import (
	"socks5"
	"socks5/protocol"
	"sync"
	"time"

	"flag"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"

	log "github.com/sirupsen/logrus"
	mux "github.com/xtaci/smux/v2"
)

/*
	1. [内网]client -> proxy -> [公网]target
	2. [公网]target -> proxy -> [内网]client
	3. Done.
	多条TCP链接分享同一个远程端口
*/

/*
{
	"actor": "server"|"client", //指定角色
	"http_server": ":9000",
	"proxy_server": "127.0.0.1:8080",
	"server_pprof_port": "10001",
	"client_pprof_port": "10002",
	"proxy_router": [
		{ "in": ":8888", "out": ":8090" }
		{ "in": ":10101", "out": ":9900" }
	],
	"socks5": {
		"verison": 5,
		"username": "hi",
		"password": "zerpro",
	},
	"kcp": {
		"key": "wdnmd",
		"salt": "hahahahahahaha",
		"crypt": "aes-128",
		"mode": "fast3",
		"mtu": 1400,
		"sndwnd": 128,
		"rcvwnd": 1024,
		"datashard": 10,
		"parityshard": 3,
		"dscp": 46,
		"acknodelay": false,
		"nodelay": 1,
		"interval": 40,
		"resend": 2,
		"sockbuf": 16777217,
	},
	"smux": {
		"version": 2,
		"keep_alive_interval": time.Duration,
		"keep_alive_timeout": time.Duration,
		"max_frame_size": 10240,
		"max_receive_buffer": 123,
		"max_stream_buffer": 123,
	}
}
*/

const (
	httpServer      = ":9000"
	proxyServer     = "127.0.0.1:8080"
	serverPprofPort = "10001"
	clientPprofPort = "10002"
)

var (
	isServer = flag.Bool("server", false, "true: server, false: client")

	// ProxyRouter => {localAddr : targetAddr}
	// localAddr 代理流量入口地址
	// targetAddr 代理流量出口地址 由代理服务器来发起连接
	ProxyRouter = map[string]string{
		":8888":  ":8090",
		":10101": ":9900",
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
	flag.Parse()
	var pprofPort string
	if *isServer {
		go server()
		pprofPort = serverPprofPort
	} else {
		go client()
		pprofPort = clientPprofPort
	}
	// TODO: HTTP API 动态修改路由
	// log.Fatal(http.ListenAndServe(httpServer, nil))
	log.Fatal(http.ListenAndServe("0.0.0.0:"+pprofPort, nil)) // pprof
}

func muxClient(conn io.ReadWriteCloser, die <-chan struct{}) {
	log.Info("muxClient start")
	defer log.Info("muxClient quit")

	buff := make([]byte, 1)
	if _, err := conn.Read(buff); err != nil {
		log.Error("[muxClient] ping recv err: ", err)
		return
	}

	session, err := mux.Client(conn, nil)
	if err != nil {
		log.Error("[muxClient] Client err: ", err)
		return
	}
	defer session.Close()

	// 根据socks5协议转发
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

	var wg sync.WaitGroup
	// 在公网机器上开启本地端口转发
	for localAddr, remoteAddr := range ProxyRouter {
		wg.Add(1)
		go func(localAddr, remoteAddr string) {
			defer wg.Done()

			if serv, err := net.Listen("tcp", localAddr); err == nil {
				defer serv.Close()
				go func() {
					<-die
					serv.Close()
				}()

				for {
					servConn, err := serv.Accept()
					if err != nil {
						log.Error("[muxClient] Inner accept err: ", err)
						return
					}
					// socks5操作
					go proxyConn(servConn, remoteAddr)
				}
			} else {
				log.Fatal("[muxClient] tcp server start err: ", err)
			}
		}(localAddr, remoteAddr)
	}
	wg.Wait()
}

func muxServer(conn io.ReadWriteCloser) {
	log.Info("muxServer start")
	defer log.Info("muxServer quit")

	if _, err := conn.Write([]byte{byte(0x01)}); err != nil {
		log.Error("[muxServer] ping err: ", err)
		return
	}
	smuxConfig := mux.DefaultConfig() // TODO: 增加smux的配置
	muxer, err := mux.Server(conn, smuxConfig)
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
	die := make(chan struct{})
	lis := protocol.New(&protocol.KcpConfig{})
	if err := lis.Listen(proxyServer); err == nil {
		defer lis.Close()
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Error("[server] Outside accept err: ", err)
				return
			}
			conn.SetReadTimeout(0)
			conn.SetWriteTimeout(0)

			// 清理原有client
			close(die)
			// 等待清理完成
			time.Sleep(time.Second)

			die = make(chan struct{})
			go muxClient(conn, die)
		}
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
