package main

import (
	"socks5"
	"socks5/protocol"

	"flag"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	mux "github.com/xtaci/smux/v2"
)

/*
多条TCP链接分享同一个远程端口
proxyMode=0:
	1. [内网]client -> proxy -> [公网]target
	2. [公网]target -> proxy -> [内网]client
	3. Done.

proxyMode=1:
	1. [内网]client -> proxy -> [公网]target
	2. Done.

*/

type route struct {
	In  string
	Out string
}

const (
	configServerFileName = "server" // 配置文件名 不带扩展名
	configClientFileName = "client" // 配置文件名 不带扩展名
)

var (
	isServer   = flag.Bool("server", false, "true->server, (default) false->client")
	configPath = flag.String("config", ".", "config file path, default in current path")

	s5                *socks5.S5Protocol
	proxyRouter       []route
	httpServer        string
	proxyMode         int
	proxyServer       string
	serverPprofServer string
	clientPprofServer string
)

func baseConfig() {
	s5 = socks5Config()
	proxyRouter = routeConfig()

	if viper.IsSet("http_server") {
		httpServer = viper.GetString("http_server")
	}
	if viper.IsSet("proxy_mode") {
		proxyMode = viper.GetInt("proxy_mode")
	}
	if viper.IsSet("proxy_server") {
		proxyServer = viper.GetString("proxy_server")
	}
	if viper.IsSet("server_pprof_server") {
		serverPprofServer = viper.GetString("server_pprof_server")
	}
	if viper.IsSet("client_pprof_server") {
		clientPprofServer = viper.GetString("client_pprof_server")
	}
}

func logConfig() {
	log.Info("================================")
	log.Info("isServer       : ", isServer)
	log.Info("httpServer     : ", httpServer)
	log.Info("proxyServer    : ", proxyServer)
	log.Info("serverPprofServer: ", serverPprofServer)
	log.Info("clientPprofServer: ", clientPprofServer)
	log.Info("socks5         : ", s5)
	log.Info("proxy router   : ", proxyRouter)
	log.Info("================================")
}

func main() {
	flag.Parse()
	var configFileName string
	if *isServer {
		configFileName = configServerFileName
	} else {
		configFileName = configClientFileName
	}
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(*configPath)
	viper.SetConfigType("json")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("config file err: ", err)
	}

	baseConfig()
	logConfig()

	var pprofServer string
	if *isServer {
		go server()
		pprofServer = serverPprofServer
	} else {
		go client()
		pprofServer = clientPprofServer
	}
	// TODO: HTTP API 动态修改路由
	// log.Fatal(http.ListenAndServe(httpServer, nil))
	log.Fatal(http.ListenAndServe(pprofServer, nil)) // pprof
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

		// 桥接流量
		socks5.ProxyStream(dst, stream)
	}

	// 在公网机器上开启本地端口转发
	var wg sync.WaitGroup
	for _, route := range proxyRouter {
		localAddr := route.In
		remoteAddr := route.Out
		wg.Add(1)
		go func(localAddr, remoteAddr string) {
			defer wg.Done()

			if serv, err := net.Listen("tcp", localAddr); err == nil {
				defer serv.Close()
				log.Info("[muxClient] listen at ", localAddr)
				go func() {
					if die != nil {
						<-die
					}
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
	muxer, err := mux.Server(conn, smuxConfig())
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
	log.Info("proxy server start")
	defer log.Info("proxy server quit")

	var die chan struct{}
	if proxyMode == 0 {
		die = make(chan struct{})
	}
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

			if proxyMode == 0 {
				close(die)              // 反方向代理时, <[内网]服务器>重启时会重新连接上<[公网]服务器>, <[公网]服务器>需要关闭上一条连接里开启的本地端口监听
				time.Sleep(time.Second) // 等待清理完成
				die = make(chan struct{})
				go muxClient(conn, die)
			} else if proxyMode == 1 {
				go muxServer(conn)
			}
		}
	}
}

func client() {
	log.Info("proxy client start")
	defer log.Info("proxy client quit")

	conn := protocol.New()
	err := conn.Dial(proxyServer)
	if err != nil {
		log.Error("[client] Dial err: ", err)
		return
	}
	defer conn.Close()
	conn.SetReadTimeout(0)
	conn.SetWriteTimeout(0)
	if proxyMode == 0 {
		muxServer(conn)
	} else if proxyMode == 1 {
		muxClient(conn, nil)
	}
}

func routeConfig() (r []route) {
	if !viper.IsSet("proxy_router") {
		return
	}
	sub := viper.Get("proxy_router")
	a, ok := sub.([]interface{})
	if !ok {
		log.Error("config proxy router err, should be []interface{}")
	}

	// 解析 proxy_router 项
	for _, val := range a {
		v, ok := val.(map[string]interface{})
		if !ok {
			log.Error("config proxy router err, should be {string: string}")
		}
		var rt route
		in, ok := v["in"]
		if !ok {
			log.Fatal("config proxy router err, must have key 'in'")
		}
		inStr, ok := in.(string)
		if !ok {
			log.Fatal("config proxy router err, key 'in' must have string value")
		}
		rt.In = inStr

		out, ok := v["out"]
		if !ok {
			log.Fatal("config proxy router err, must have key 'out'")
		}
		outStr, ok := out.(string)
		if !ok {
			log.Fatal("config proxy router err, key 'out' must have string value")
		}
		rt.Out = outStr

		r = append(r, rt)
	}
	return
}

func socks5Config() (s5 *socks5.S5Protocol) {
	s5 = &socks5.S5Protocol{
		Version:           5,
		AuthMethodSupport: []byte{socks5.AuthNoAuthRequired},
		DirectMode:        true,
		ConnConfig:        kcpConfig(),
	}
	if !viper.IsSet("socks5") {
		return
	}
	// 此项不起作用
	if viper.IsSet("socks5.version") {
		s5.Version = byte(viper.GetInt("socks5.version"))
	}
	if viper.IsSet("socks5.username") {
		s5.Username = viper.GetString("socks5.username")
		s5.AuthMethodSupport = append(s5.AuthMethodSupport, socks5.AuthUsernamePasswd)
	}
	if viper.IsSet("socks5.password") {
		s5.Password = viper.GetString("socks5.password")
	}
	return
}

func kcpConfig() (config *protocol.KcpConfig) {
	if !viper.IsSet("kcp") {
		return
	}
	config = &protocol.KcpConfig{}
	if viper.IsSet("kcp.key") {
		config.Key = viper.GetString("kcp.key")
	}
	if viper.IsSet("kcp.salt") {
		config.Salt = viper.GetString("kcp.salt")
	}
	if viper.IsSet("kcp.crypt") {
		config.Crypt = viper.GetString("kcp.crypt")
	}
	if viper.IsSet("kcp.mode") {
		config.Mode = viper.GetString("kcp.mode")
	}
	if viper.IsSet("kcp.mtu") {
		config.MTU = viper.GetInt("kcp.mtu")
	}
	if viper.IsSet("kcp.sndwnd") {
		config.SndWnd = viper.GetInt("kcp.sndwnd")
	}
	if viper.IsSet("kcp.rcvwnd") {
		config.RcvWnd = viper.GetInt("kcp.rcvwnd")
	}
	if viper.IsSet("kcp.datashard") {
		config.DataShard = viper.GetInt("kcp.datashard")
	}
	if viper.IsSet("kcp.parityshard") {
		config.ParityShard = viper.GetInt("kcp.parityshard")
	}
	if viper.IsSet("kcp.dscp") {
		config.DSCP = viper.GetInt("kcp.dscp")
	}
	if viper.IsSet("kcp.acknodelay") {
		config.AckNodelay = viper.GetBool("kcp.acknodelay")
	}
	if viper.IsSet("kcp.interval") {
		config.Interval = viper.GetInt("kcp.interval")
	}
	if viper.IsSet("kcp.resend") {
		config.Resend = viper.GetInt("kcp.resend")
	}
	if viper.IsSet("kcp.sockbuf") {
		config.SockBuf = viper.GetInt("kcp.sockbuf")
	}

	return
}

func smuxConfig() (config *mux.Config) {
	config = mux.DefaultConfig() // TODO: 增加smux的配置
	if !viper.IsSet("smux") {
		return
	}
	if viper.IsSet("smux.keep_alive_interval") {
		config.KeepAliveInterval = viper.GetDuration("smux.keep_alive_interval") * time.Second
	}
	if viper.IsSet("smux.keep_alive_timeout") {
		config.KeepAliveTimeout = viper.GetDuration("smux.keep_alive_timeout") * time.Second
	}
	if viper.IsSet("smux.max_frame_size") {
		config.MaxFrameSize = viper.GetInt("smux.max_frame_size")
	}
	if viper.IsSet("smux.max_receive_buffer") {
		config.MaxFrameSize = viper.GetInt("smux.max_receive_buffer")
	}
	if viper.IsSet("smux.max_stream_buffer") {
		config.MaxStreamBuffer = viper.GetInt("smux.max_stream_buffer")
	}
	return
}
