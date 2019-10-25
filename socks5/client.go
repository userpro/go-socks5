package socks5

import (
	"socks5/protocol"

	"fmt"
	"time"
)

// Client socks5 客户端
type Client struct {
	conn                      protocol.ClientConn
	proxyServer               string
	readTimeout, writeTimeout time.Duration
	s5                        *S5Protocol
}

// ClientOpts 相关参数
type ClientOpts struct {
	Methods                   []byte
	Username, Password        string
	ReadTimeout, WriteTimeout time.Duration
}

// NewClient 新建一个socks5客户端 默认无timeout 阻塞
func NewClient() *Client {
	return &Client{
		conn: protocol.New(),
		s5:   NewS5Protocol(),
	}
}

// NewClientWithConn 新建一个socks5客户端 已有连接
func NewClientWithConn(conn protocol.ClientConn) *Client {
	return &Client{
		conn: conn,
		s5: &S5Protocol{
			Version:           5,
			AuthMethodSupport: []byte{AuthNoAuthRequired},
		},
	}
}

// NewClientWithOpts 新建一个socks5客户端并设置
func NewClientWithOpts(opts *ClientOpts) *Client {
	return NewClient().setOpts(opts)
}

// NewClientConnWithOpts 新建一个socks5客户端并设置 已有连接
func NewClientConnWithOpts(conn protocol.ClientConn, opts *ClientOpts) *Client {
	return NewClientWithConn(conn).setOpts(opts)
}

func (c *Client) setOpts(opts *ClientOpts) *Client {
	if opts != nil {
		if opts.Username != "" {
			c.s5.AuthMethodSupport = append(c.s5.AuthMethodSupport, AuthUsernamePasswd)
		}
		c.s5.AuthMethodSupport = append(c.s5.AuthMethodSupport, opts.Methods...)
		c.s5.Username = opts.Username
		c.s5.Password = opts.Password
		c.readTimeout = opts.ReadTimeout
		c.writeTimeout = opts.WriteTimeout
	}
	return c
}

// Dial 连接socks5代理服务器
func (c *Client) Dial(proxyAddr string) (err error) {
	if c.readTimeout >= 0 {
		c.conn.SetReadTimeout(c.readTimeout)
	}
	if c.writeTimeout >= 0 {
		c.conn.SetWriteTimeout(c.writeTimeout)
	}

	if err = c.conn.Dial(proxyAddr); err != nil {
		return fmt.Errorf("<conn dial %s err: %w>", proxyAddr, err)
	}
	c.proxyServer = proxyAddr

	return c.s5.Dial(c.conn)
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.conn.Close()
}

// Connect 通过代理服务器连接目标服务器
func (c *Client) Connect(dstAddr string) (bindAddr string, err error) {
	return c.s5.Connect(c.conn, c.proxyServer, dstAddr)
}
