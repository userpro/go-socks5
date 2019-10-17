package socks5

import (
	"socks5/protocol"

	"errors"
	"fmt"
	"strconv"
)

// Client socks5 客户端
type Client struct {
	version          byte
	authMethodChoose byte
	authMethodCan    []byte
	username, passwd string

	conn protocol.Conn

	dstServer map[string]protocol.Conn // 目标服务器可以有多个
}

// NewClient 新建一个socks5客户端
func NewClient(version int, methods []byte, username, passwd string) *Client {
	if version == 0 {
		version = 5
	}
	if methods == nil {
		methods = []byte{AuthNoAuthRequired}
		if username != "" {
			methods = append(methods, AuthUsernamePasswd)
		}
	}

	return &Client{
		version:       byte(version),
		authMethodCan: methods,
		username:      username,
		passwd:        passwd,

		conn: protocol.New(),
	}
}

// Dial 连接socks5代理服务器
func (c *Client) Dial(proxyAddr, proxyPort string) (err error) {
	frame := &Frame{}

	if proxyAddr == "localhost" {
		proxyAddr = "127.0.0.1"
	}
	if err = c.conn.Dial(proxyAddr, proxyPort); err != nil {
		return fmt.Errorf("<conn dial %s:%s err: %w>", proxyAddr, proxyPort, err)
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
	buff := make([]byte, 2)
	if _, err = c.conn.ReadFull(buff); err != nil {
		return fmt.Errorf("<ServerAuthResponse readFull failed> %w ", err)
	}

	if err = c.checkVersion(buff[0]); err != nil {
		return fmt.Errorf("<ServerAuthResponse> %w", err)
	}

	// 选定鉴权方式
	c.authMethodChoose = buff[1]
	return c.authDo(frame)
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) checkVersion(version byte) (err error) {
	if version != c.version {
		return fmt.Errorf("<version incorrect, need socks %d>", c.version)
	}
	return
}

func (c *Client) authDo(frame *Frame) (err error) {
	// 无须验证
	if c.authMethodChoose == AuthNoAuthRequired {
		return nil
	}

	if c.authMethodChoose != AuthUsernamePasswd {
		return errors.New("<unsupport auth type>")
	}

	// 客户端发送验证数据包
	// version | username_length | username | password_length | password
	// 1 		 1 				   1-255 	  1 			    1-255
	if _, err = c.conn.Write(frame.ClientUsernamePasswdRequest(c.version, c.username, c.passwd)); err != nil {
		return fmt.Errorf("<auth write err> %w ", err)
	}

	// 服务端响应验证包
	// version | status
	// 1 	     1
	buff := make([]byte, 2)
	if _, err = c.conn.ReadFull(buff); err != nil {
		return errors.New("<auth readFull failed>")
	}

	if err = c.checkVersion(buff[0]); err != nil {
		return fmt.Errorf("<auth version incorrect> %w", err)
	}

	// 认证失败
	if buff[1] != 0 {
		return errors.New("<auth failed>")
	}

	return nil
}

// Connect 通过代理服务器连接目标服务器
func (c *Client) Connect(dstAddr, dstPort string, cmd byte) (conn protocol.Conn, err error) {
	frame := &Frame{}

	conn, ok := c.dstServer[dstAddr+":"+dstPort]
	if ok {
		return conn, nil
	}

	if dstAddr == "localhost" {
		dstAddr = "127.0.0.1"
	}

	// 客户端发送指令
	// +-----+---------+-----+--------------+----------+----------+
	// | VER | COMMAND | RSV | ADDRESS_TYPE | DST.ADDR | DST.PORT |
	// +-----+---------+-----+--------------+----------+----------+
	// |   1 |       1 |   1 |            1 | 1-255    |        2 |
	// +-----+---------+-----+--------------+----------+----------+
	if _, err = c.conn.Write(frame.ClientCommandRequest(c.version, cmd, byte(0), dstAddr, dstPort)); err != nil {
		return
	}

	// 代理服务器响应
	// +-----+----------+-----+--------------+-----------+-----------+
	// | VER | RESPONSE | RSV | ADDRESS_TYPE | BIND.ADDR | BIND.PORT |
	// +-----+----------+-----+--------------+-----------+-----------+
	// |   1 |        1 |   1 |            1 | 1-255     |         2 |
	// +-----+----------+-----+--------------+-----------+-----------+
	buff := make([]byte, 3)
	if _, err = c.conn.ReadFull(buff); err != nil {
		return
	}

	if err = c.checkVersion(buff[0]); err != nil {
		return nil, fmt.Errorf("<client connect> %w", err)
	}

	if buff[1] != 0 {
		return nil, errors.New(ReplyMessage[buff[1]])
	}

	bindAddr, bindPort, err := ReadAddress(c.conn)
	if err != nil {
		return nil, err
	}

	log.Info("[client.Connect]", bindAddr, ":", bindPort)
	conn = protocol.New()
	if err = conn.Dial(bindAddr, bindPort); err != nil {
		return nil, fmt.Errorf(" conn dial %s:%s err: %w ", bindAddr, bindPort, err)
	}

	return
}

// ReadAddress data
// +--------------+----------+----------+
// | ADDRESS_TYPE | DST.ADDR | DST.PORT |
// +--------------+----------+----------+
// |           1  | 1-255    |        2 |
// +--------------+----------+----------+
func ReadAddress(c protocol.Conn) (addr, port string, err error) {
	buff := make([]byte, 1)
	if _, err = c.ReadFull(buff); err != nil {
		return
	}

	addrType := buff[0]
	switch addrType {
	case AddrIPv4:
		buff = make([]byte, 4)
		if _, err = c.ReadFull(buff); err != nil {
			err = fmt.Errorf("<invalid ipv4 address> %w", err)
			return
		}
		addr = IPv4ByteToStr(buff)
	case AddrIPv6:
		buff = make([]byte, 16)
		if _, err = c.ReadFull(buff); err != nil {
			err = fmt.Errorf("<invalid ipv6 address> %w", err)
			return
		}
		addr = IPv6ByteToStr(buff)
	case AddrDomain:
		// 域名地址的第1个字节为域名长度, 剩下字节为域名名称字节数组
		buff = make([]byte, 1)
		if _, err = c.ReadFull(buff); err != nil {
			err = fmt.Errorf("<invalid domain address> %w", err)
			return
		}
		domainLen := buff[1]
		if domainLen > 0 {
			buff = make([]byte, domainLen)
			if _, err = c.ReadFull(buff); err != nil {
				err = fmt.Errorf("<invalid domain address> %w", err)
				return
			}
		}
		addr = string(buff)
	default:
		err = fmt.Errorf("<unknown address type %d>", addrType)
		return
	}

	buff = make([]byte, 2)
	if _, err = c.ReadFull(buff); err != nil {
		err = fmt.Errorf("<invalid port> %w", err)
		return
	}
	port = strconv.Itoa(int(ByteToUint16(buff)))

	return
}
