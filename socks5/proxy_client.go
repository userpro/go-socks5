package socks5

import (
	"socks5/protocol"

	"net"
	"strings"
)

// ProxyClient 客户端代理
type ProxyClient struct {
	proxyServer string
}

// Proxy 创建一个代理客户端
func (p *ProxyClient) Proxy(proxyServer string, proxyRouter map[string]string, opts *ClientOpts) {
	p.proxyServer = proxyServer
	if strings.HasPrefix(p.proxyServer, ":") {
		p.proxyServer = "0.0.0.0" + p.proxyServer
	}

	// proxyRouter => {localAddress : dstAddress}
	for localAddress, dstAddress := range proxyRouter {
		go p.localServer(localAddress, dstAddress, opts)
	}
	for {
	}
}

func (p *ProxyClient) localServer(localAddress, dstAddress string, opts *ClientOpts) {
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

		go func(p1 net.Conn) {
			var p2 protocol.Conn
			// socks5 认证
			s5Client := NewClientWithOpts(opts)
			defer s5Client.Close()

			if err := s5Client.Dial(p.proxyServer); err != nil {
				log.Error("[ProxyClient.proxyConn] Dial failed ", err)
				p1.Close()
				return
			}
			log.Info("[ProxyClient.proxyConn] socks5 handshake ok")

			bindAddr, err := s5Client.Connect(dstAddress, CmdConnect)
			if err != nil {
				log.Error("[ProxyClient.proxyConn] Command err: ", err)
				p1.Close()
				return
			}

			// 连接绑定端口
			p2 = protocol.New()
			if err := p2.Dial(bindAddr); err != nil {
				log.Errorf("[ProxyClient.Listen] <conn dial %s err: %v >", bindAddr, err)
				p1.Close()
				return
			}

			handleClient(p2, p1)
		}(clientConn)
	}
}
