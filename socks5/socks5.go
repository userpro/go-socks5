package socks5

import (
	"socks5/protocol"

	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

var s5Buf sync.Pool

func init() {
	s5Buf.New = func() interface{} {
		return make([]byte, 10240)
	}
}

// S5Protocol 协议实现
type S5Protocol struct {
	version            byte
	username, password string
	authMethodSupport  []byte // 双方支持的认证方式
	authMethodChoose   byte   // 双方最终协商决定

	directMode bool // 自定义模式 connect时不去链接 bind address, 直接复用socks5认证链接.
}

// NewS5Protocol 协议体
func NewS5Protocol() *S5Protocol {
	return &S5Protocol{
		version:           5,
		authMethodSupport: []byte{AuthNoAuthRequired},
	}
}

// SetDirectMode 设置是否为直连模式 默认false=off true=on
func (s *S5Protocol) SetDirectMode(direct bool) { s.directMode = direct }

// Server 服务端流程
func (s *S5Protocol) Server(conn io.ReadWriteCloser) {
	defer conn.Close()

	frame := &Frame{}
	var totalBuff [256]byte

	// 客户端支持的认证方法数
	// +-----+---------------+
	// | VER | METHOD_COUNTS |
	// +-----+---------------+
	// |   1 |             1 |
	// +-----+---------------+
	buff := totalBuff[:2]
	if _, err := s.ReadFull(conn, buff); err != nil {
		log.Error("[authConn] Read header err: ", err)
		return
	}

	if err := s.isSameVersion(buff[0]); err != nil {
		log.Error("[authConn] isSameVersion err: ", err)
		return
	}

	// methods(由之前method_counts决定)
	methodCount := buff[1]
	if methodCount > 0 {
		buff = totalBuff[:methodCount]
		if _, err := s.ReadFull(conn, buff); err != nil {
			log.Error("[authConn] Read methods err: ", err)
			return
		}
	} else {
		buff = []byte{AuthNoAuthRequired}
	}

	var chooseAuthMethod byte
	for _, v1 := range s.authMethodSupport {
		for _, v2 := range buff {
			if v1 == v2 {
				chooseAuthMethod = v1
			}
		}
	}

	if _, err := conn.Write(frame.ServerAuthResponse(s.version, chooseAuthMethod)); err != nil {
		log.Error("[authConn] ServerAuthResponse write err: ", err)
		return
	}

	switch chooseAuthMethod {
	case AuthNoAuthRequired:
		// 没有认证 Do Nothing
	case AuthUsernamePasswd:
		// 用户名密码验证
		err := s.servAuthUsernamePasswd(conn, totalBuff[:], frame)
		if err != nil {
			log.Error("[authConn] servAuthUsernamePasswd err: ", err)
			return
		}

	default:
		log.Error("[authConn] unknown auth type ")
		return
	}

	s.servHandleCommand(conn, totalBuff[:], frame)
}

func (s *S5Protocol) isSameVersion(version byte) (err error) {
	if version != s.version {
		return fmt.Errorf("<version incorrect, need socks %d>", s.version)
	}
	return
}

// +---------+-----------------+----------+-----------------+----------+
// | VERSION | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
// +---------+-----------------+----------+-----------------+----------+
// |       1 |               1 | 1-255    |               1 | 1-255    |
// +---------+-----------------+----------+-----------------+----------+
func (s *S5Protocol) servAuthUsernamePasswd(conn io.ReadWriteCloser, totalBuff []byte, frame *Frame) (err error) {
	buff := totalBuff[:2]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return
	}

	if err = s.isSameVersion(buff[0]); err != nil {
		return
	}

	var username, passwd []byte
	// 读取username
	unameLen := buff[1]
	if unameLen < 0 {
		return errors.New("<uname length is zero>")
	}

	buff = totalBuff[:unameLen]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return
	}
	username = make([]byte, unameLen)
	copy(username, buff)

	// 读取passwd
	buff = make([]byte, 1)
	if _, err = s.ReadFull(conn, buff); err != nil {
		return
	}
	passwdLen := buff[0]
	if passwdLen < 0 {
		return errors.New("<passwd length is zero>")
	}
	buff = totalBuff[:passwdLen]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return
	}
	passwd = make([]byte, passwdLen)
	copy(passwd, buff)

	// ServerUsernamePasswdResponse 第二个参数为status > 0 failed, = 0 success
	if s.username == string(username) && s.password == string(passwd) {
		if _, err := conn.Write(frame.ServerUsernamePasswdResponse(s.version, 0)); err != nil {
			return fmt.Errorf("<Write error> %w", err)
		}
		return nil
	}

	if _, err = conn.Write(frame.ServerUsernamePasswdResponse(s.version, 100)); err != nil {
		return fmt.Errorf("<Write error> %w", err)
	}
	return errors.New("<username/passwd dismatch>")
}

// 处理command
func (s *S5Protocol) servHandleCommand(conn io.ReadWriteCloser, totalBuff []byte, frame *Frame) {
	// +-----+---------+-----+
	// | VER | COMMAND | RSV |
	// +-----+---------+-----+
	// |   1 |       1 |   1 |
	// +-----+---------+-----+
	buff := totalBuff[:3]
	if _, err := s.ReadFull(conn, buff); err != nil {
		log.Error("[servHandleCommand] read err: ", err)
		return
	}

	if err := s.isSameVersion(buff[0]); err != nil {
		log.Error("[servHandleCommand] isSameVersion err: ", err)
		return
	}

	switch buff[1] {
	case CmdConnect:
		s.servDoConnect(conn, frame)
	case CmdBind:
		s.servDoBind(conn, frame)
		fallthrough
	case CmdUDP:
		s.servDoUDP(conn, frame)
		fallthrough
	default:
		if _, err := conn.Write(frame.ServerCommandResponse(s.version, ReplyCommandNotSupport, byte(0), "", "")); err != nil {
			log.Error("[servHandleCommand] CommandNotSupport ", err)
		}
	}
}

func (s *S5Protocol) servDoConnect(conn io.ReadWriteCloser, frame *Frame) {
	// +--------------+----------+----------+
	// | ADDRESS_TYPE | BND.ADDR | BND.PORT |
	// +--------------+----------+----------+
	// |            1 | 1-255    |        2 |
	// +--------------+----------+----------+
	addr, port, err := ReadAddress(conn)
	if err != nil {
		log.Error("[servDoConnect] ReadAddress ", err)
		return
	}

	// 测试目标是否可达 同时获取一个可用端口
	p2, err := net.Dial("tcp", addr+":"+port)
	if err != nil {
		log.Error("[servDoConnect] Dail err: ", err)
		if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplyNetworkUnreachable, byte(0), "", "")); err != nil {
			log.Error("[servDoConnect] ServerCommandResponse err: ", err)
		}
		return
	}

	// 直连模式
	if s.directMode {
		ProxyStream(conn, p2)
		return
	}

	bindIP := "0.0.0.0"
	bindPort := strings.Split(p2.LocalAddr().String(), ":")[1]

	// 开启端口转发监听 等待客户端连接
	server := protocol.New()
	if err = server.Listen(bindIP + ":" + bindPort); err != nil {
		log.Error("[servDoConnect] listen err: ", err)
		if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplySOCKSServerFailure, byte(0), "", "")); err != nil {
			log.Error("[servDoConnect] ServerCommandResponse err: ", err)
		}
		p2.Close()
		return
	}

	// 响应客户端command数据包
	if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplySuccess, byte(0), bindIP, bindPort)); err != nil {
		log.Error("[servDoConnect] ServerCommandResponse err: ", err)
		p2.Close()
		server.Close()
		return
	}

	// 转发端口流量
	go func() {
		defer server.Close()
		p1, err := server.Accept()
		if err != nil {
			log.Error("[servDoConnect] proxy port accept err: ", err)
			return
		}

		ProxyStream(p1, p2)
	}()

	return
}

func (s *S5Protocol) servDoBind(conn io.ReadWriteCloser, frame *Frame) (err error) {
	return
}

func (s *S5Protocol) servDoUDP(conn io.ReadWriteCloser, frame *Frame) (err error) {
	return
}

// Dial socks5发起端
func (s *S5Protocol) Dial(conn io.ReadWriteCloser) (err error) {
	frame := &Frame{}
	var totalBuff [8]byte

	// 客户端发送握手包
	// 一、客户端认证请求
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     |  1~255   |
	// +----+----------+----------+
	if _, err = conn.Write(frame.ClientAuthRequest(s.version, s.authMethodSupport)); err != nil {
		return fmt.Errorf("<conn write ClientAuthRequest err: %w>", err)
	}

	// 服务端响应握手 选择验证方式
	// +-----+--------+
	// | VER | MEHTOD |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	buff := totalBuff[:2]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return fmt.Errorf("<ServerAuthResponse readFull failed> %w ", err)
	}

	if err = s.isSameVersion(buff[0]); err != nil {
		return fmt.Errorf("<ServerAuthResponse> %w", err)
	}

	// 选定鉴权方式
	s.authMethodChoose = buff[1]
	return s.clientAuth(conn, totalBuff[:], frame)
}

func (s *S5Protocol) clientAuth(conn io.ReadWriteCloser, totalBuff []byte, frame *Frame) (err error) {
	// 无须验证
	if s.authMethodChoose == AuthNoAuthRequired {
		return nil
	}

	if s.authMethodChoose != AuthUsernamePasswd {
		return errors.New("<unsupport auth type>")
	}

	// 客户端发送验证数据包
	// +-----+-----------------+----------+-----------------+----------+
	// | VER | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
	// +-----+-----------------+----------+-----------------+----------+
	// |   1 |               1 | 1-255    |               1 | 1-255    |
	// +-----+-----------------+----------+-----------------+----------+
	if _, err = conn.Write(frame.ClientUsernamePasswdRequest(s.version, s.username, s.password)); err != nil {
		return fmt.Errorf("<auth write err> %w ", err)
	}

	// 服务端响应验证包
	// +-----+--------+
	// | VER | STATUS |
	// +-----+--------+
	// |   1 |      1 |
	// +-----+--------+
	buff := totalBuff[:2]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return errors.New("<auth readFull failed>")
	}

	if err = s.isSameVersion(buff[0]); err != nil {
		return fmt.Errorf("<auth version incorrect> %w", err)
	}

	// 认证失败
	if buff[1] != 0 {
		return errors.New("<auth failed>")
	}

	return nil
}

// Connect 客户端发起connect指令
func (s *S5Protocol) Connect(conn io.ReadWriteCloser, proxyAddr, dstAddr string) (bindAddr string, err error) {
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
	if _, err = conn.Write(frame.ClientCommandRequest(s.version, CmdConnect, byte(0), ip, port)); err != nil {
		return
	}

	// 代理服务器响应
	// +-----+----------+-----+--------------+-----------+-----------+
	// | VER | RESPONSE | RSV | ADDRESS_TYPE | BIND.ADDR | BIND.PORT |
	// +-----+----------+-----+--------------+-----------+-----------+
	// |   1 |        1 |   1 |            1 | 1-255     |         2 |
	// +-----+----------+-----+--------------+-----------+-----------+
	buff := totalBuff[:3]
	if _, err = s.ReadFull(conn, buff); err != nil {
		return
	}

	if err = s.isSameVersion(buff[0]); err != nil {
		return "", fmt.Errorf("<client connect> %w", err)
	}

	if buff[1] != 0 {
		return "", errors.New(ReplyMessage[buff[1]])
	}

	// 获取服务器响应的 地址:端口
	_, bindPort, err := ReadAddress(conn)
	if err != nil {
		return
	}

	bindIP := strings.Split(proxyAddr, ":")[0]
	bindAddr = bindIP + ":" + bindPort
	return
}

// ProxyStream 转发流
func ProxyStream(p1 io.ReadWriteCloser, p2 net.Conn) {
	defer p1.Close()
	defer p2.Close()

	if s1, ok := p1.(protocol.Stream); ok {
		log.Info("stream open in:", s1.RemoteAddr().String(), " out:", p2.LocalAddr().String())
		defer log.Info("stream close in:", s1.RemoteAddr().String(), " out:", p2.LocalAddr().String())
	}

	streamCopy := func(dst io.Writer, src io.ReadCloser) chan struct{} {
		die := make(chan struct{})
		go func() {
			buff := s5Buf.Get().([]byte)
			if _, err := io.CopyBuffer(dst, src, buff); err != nil {
				log.Error("[streamCopy] err: ", err)
			}
			s5Buf.Put(buff)
			close(die)
		}()
		return die
	}

	select {
	case <-streamCopy(p1, p2):
	case <-streamCopy(p2, p1):
	}
}

// ReadAddress data
// +--------------+----------+----------+
// | ADDRESS_TYPE | DST.ADDR | DST.PORT |
// +--------------+----------+----------+
// |           1  | 1-255    |        2 |
// +--------------+----------+----------+
func ReadAddress(c io.ReadWriteCloser) (addr, port string, err error) {
	var totalBuff [16]byte
	buff := totalBuff[:1]
	if _, err = c.Read(buff); err != nil {
		return
	}

	addrType := buff[0]
	switch addrType {
	case AddrIPv4:
		buff = totalBuff[:4]
		if _, err = c.Read(buff); err != nil {
			err = fmt.Errorf("<invalid ipv4 address> %w", err)
			return
		}
		addr = IPv4ByteToStr(buff)
	case AddrIPv6:
		buff = totalBuff[:16]
		if _, err = c.Read(buff); err != nil {
			err = fmt.Errorf("<invalid ipv6 address> %w", err)
			return
		}
		addr = IPv6ByteToStr(buff)
	case AddrDomain:
		// 域名地址的第1个字节为域名长度, 剩下字节为域名名称字节数组
		buff = totalBuff[:1]
		if _, err = c.Read(buff); err != nil {
			err = fmt.Errorf("<invalid domain address> %w", err)
			return
		}
		domainLen := buff[1]
		if domainLen > 0 {
			buff = totalBuff[:domainLen]
			if _, err = c.Read(buff); err != nil {
				err = fmt.Errorf("<invalid domain address> %w", err)
				return
			}
		}
		addr = string(buff)
	default:
		err = fmt.Errorf("<unknown address type %d>", addrType)
		return
	}

	buff = totalBuff[:2]
	if _, err = c.Read(buff); err != nil {
		err = fmt.Errorf("<invalid port> %w", err)
		return
	}
	port = strconv.Itoa(int(ByteToUint16(buff)))

	return
}

// ReadFull 从conn中读取len(buff)数据
func (s *S5Protocol) ReadFull(conn io.ReadWriteCloser, buff []byte) (nread int, err error) {
	var totalRead int
	for {
		if totalRead >= len(buff) {
			return
		}
		if nread, err = conn.Read(buff[totalRead:]); err != nil {
			return
		}
		totalRead += nread
	}
}
