package socks5

import (
	"socks5/protocol"

	"io"
	"net"
	"net/http"
)

// ProxyClient 客户端代理
type ProxyClient struct {
	HTTPServer  string
	ProxyServer string
	ProxyRouter map[string]string
	Opts        *ClientOpts
}

// Proxy 创建一个代理客户端
func (p *ProxyClient) Proxy() {
	if p.ProxyServer == "" || p.ProxyRouter == nil {
		return
	}

	// ProxyRouter => {localAddress : dstAddress}
	for localAddress, dstAddress := range p.ProxyRouter {
		go p.localServer(localAddress, dstAddress)
	}

	// TODO: HTTP服务 web端动态编辑路由
	if p.HTTPServer != "" {
		p.httpAPI()
	}
}

func (p *ProxyClient) httpAPI() {
	h1 := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}
	http.HandleFunc("/", h1)
	log.Fatal(http.ListenAndServe(p.HTTPServer, nil))
}

func (p *ProxyClient) localServer(localAddress, dstAddress string) {
	listen, err := net.Listen("tcp", localAddress)
	if err != nil {
		log.Error("[ProxyClient.localServer] Listen err: ", err)
		return
	}
	defer listen.Close()

	for {
		clientConn, err := listen.Accept()
		if err != nil {
			log.Error("[ProxyClient.localServer] Accept err: ", err)
			return
		}
		// log.Info("[ProxyClient.localServer] ", clientConn.RemoteAddr().String(), " -> ", clientConn.LocalAddr().String())

		go func(p1 net.Conn) {
			defer p1.Close()
			var p2 protocol.Conn
			// socks5 认证
			s5Client := NewClientWithOpts(p.Opts)
			if err := s5Client.Dial(p.ProxyServer); err != nil {
				log.Error("[ProxyClient.proxyConn] Dial failed err: ", err)
				return
			}

			bindAddr, err := s5Client.Connect(dstAddress, CmdConnect)
			if err != nil {
				log.Error("[ProxyClient.proxyConn] Command err: ", err)
				return
			}
			s5Client.Close()

			// 连接绑定端口
			log.Info("[ProxyClient.Listen] bind Addr: ", bindAddr)
			p2 = protocol.New()
			if err := p2.Dial(bindAddr); err != nil {
				log.Errorf("[ProxyClient.Listen] <conn dial %s err: %v >", bindAddr, err)
				return
			}

			handleClient(p2, p1)
		}(clientConn)
	}
}
