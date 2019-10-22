package socks5

import (
	"socks5/protocol"

	"errors"
	"fmt"
	"strings"
	"time"
)

// Client socks5 客户端
type Client struct {
	version            byte
	authMethodChoose   byte
	authMethodCan      []byte
	username, password string

	conn                      protocol.Conn
	readTimeout, writeTimeout time.Duration
}

// ClientOpts 相关参数
type ClientOpts struct {
	Methods                   []byte
	Username, Password        string
	ReadTimeout, WriteTimeout time.Duration
}

// NewClient 新建一个socks5客户端 默认无timeout
func NewClient() *Client {
	return &Client{
		version:       5,
		authMethodCan: []byte{AuthNoAuthRequired},
		conn:          protocol.New(),
	}
}

// NewClientWithOpts 带设置客户端
func NewClientWithOpts(opts *ClientOpts) *Client {
	client := NewClient()
	if opts != nil {
		if opts.Username != "" {
			client.authMethodCan = append(client.authMethodCan, AuthUsernamePasswd)
		}
		client.username = opts.Username
		client.password = opts.Password
		client.readTimeout = opts.ReadTimeout
		client.writeTimeout = opts.WriteTimeout
	}
	return client
}

// Dial 连接socks5代理服务器
func (c *Client) Dial(proxyAddr string) (err error) {
	if c.readTimeout >= 0 {
		c.conn.SetReadTimeout(c.readTimeout)
	}
	if c.writeTimeout >= 0 {
		c.conn.SetWriteTimeout(c.writeTimeout)
	}

	frame := &Frame{}
	var totalBuff [8]byte

	if err = c.conn.Dial(proxyAddr); err != nil {
		return fmt.Errorf("<conn dial %s:%s err: %w>", proxyAddr, err)
	}

	// 客户端发送握手包
	// 一、客户端认证请求
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     |  1~255   |
	// +----+----------+----------+
	if _, err = c.conn.Write(frame.ClientAuthRequest(c.version, c.authMethodCan)); err != nil {
		return fmt.Errorf("<conn write ClientAuthRequest err: %w>", err)
	}

	// 服务端响应握手 选择验证方式
	// +-----+--------+
	// | VER | MEHTOD |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	buff := totalBuff[:2]
	if _, err = c.conn.ReadFull(buff); err != nil {
		return fmt.Errorf("<ServerAuthResponse readFull failed> %w ", err)
	}

	if err = c.isSameVersion(buff[0]); err != nil {
		return fmt.Errorf("<ServerAuthResponse> %w", err)
	}

	// 选定鉴权方式
	c.authMethodChoose = buff[1]
	return c.isAuth(totalBuff[:], frame)
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) isSameVersion(version byte) (err error) {
	if version != c.version {
		return fmt.Errorf("<version incorrect, need socks %d>", c.version)
	}
	return
}

func (c *Client) isAuth(totalBuff []byte, frame *Frame) (err error) {
	// 无须验证
	if c.authMethodChoose == AuthNoAuthRequired {
		return nil
	}

	if c.authMethodChoose != AuthUsernamePasswd {
		return errors.New("<unsupport auth type>")
	}

	// 客户端发送验证数据包
	// +-----+-----------------+----------+-----------------+----------+
	// | VER | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
	// +-----+-----------------+----------+-----------------+----------+
	// |   1 |               1 | 1-255    |               1 | 1-255    |
	// +-----+-----------------+----------+-----------------+----------+
	if _, err = c.conn.Write(frame.ClientUsernamePasswdRequest(c.version, c.username, c.password)); err != nil {
		return fmt.Errorf("<auth write err> %w ", err)
	}

	// 服务端响应验证包
	// +-----+--------+
	// | VER | STATUS |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	buff := totalBuff[:2]
	if _, err = c.conn.ReadFull(buff); err != nil {
		return errors.New("<auth readFull failed>")
	}

	if err = c.isSameVersion(buff[0]); err != nil {
		return fmt.Errorf("<auth version incorrect> %w", err)
	}

	// 认证失败
	if buff[1] != 0 {
		return errors.New("<auth failed>")
	}

	return nil
}

// Connect 通过代理服务器连接目标服务器
func (c *Client) Connect(dstAddr string, cmd byte) (bindAddr string, err error) {
	frame := &Frame{}
	var totalBuff [8]byte

	var ip, port string
	addr := strings.Split(dstAddr, ":")
	ip, port = addr[0], addr[1]
	if ip == "localhost" || ip == "" {
		ip = "127.0.0.1"
	}
	// log.Info("[Connect] ", ip, ":", port)

	// 客户端发送指令
	// +-----+---------+-----+--------------+----------+----------+
	// | VER | COMMAND | RSV | ADDRESS_TYPE | DST.ADDR | DST.PORT |
	// +-----+---------+-----+--------------+----------+----------+
	// |   1 |       1 |   1 |            1 | 1-255    |        2 |
	// +-----+---------+-----+--------------+----------+----------+
	if _, err = c.conn.Write(frame.ClientCommandRequest(c.version, cmd, byte(0), ip, port)); err != nil {
		return
	}

	// 代理服务器响应
	// +-----+----------+-----+--------------+-----------+-----------+
	// | VER | RESPONSE | RSV | ADDRESS_TYPE | BIND.ADDR | BIND.PORT |
	// +-----+----------+-----+--------------+-----------+-----------+
	// |   1 |        1 |   1 |            1 | 1-255     |         2 |
	// +-----+----------+-----+--------------+-----------+-----------+
	buff := totalBuff[:3]
	if _, err = c.conn.ReadFull(buff); err != nil {
		return
	}

	if err = c.isSameVersion(buff[0]); err != nil {
		return "", fmt.Errorf("<client connect> %w", err)
	}

	if buff[1] != 0 {
		return "", errors.New(ReplyMessage[buff[1]])
	}

	// 获取服务器响应的 地址:端口
	_, bindPort, err := ReadAddress(c.conn)
	if err != nil {
		return
	}
	// bindIP 即是socks5服务器的IP
	bindIP := strings.Split(c.conn.RemoteAddr().String(), ":")[0]
	bindAddr = bindIP + ":" + bindPort
	return
}
