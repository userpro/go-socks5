package socks5

import (
	"socks5/protocol"

	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Server socks5 服务端
type Server struct {
	version  byte
	conn     protocol.Conn
	deadline time.Duration

	supportAuthMethod []byte // 支持的认证方式
	username, passwd  string
}

// NewServer 创建server
func NewServer(version int, username, passwd string, deadline time.Duration) *Server {
	supportAuthMethod := []byte{AuthNoAuthRequired}
	if username != "" {
		supportAuthMethod = append(supportAuthMethod, AuthUsernamePasswd)
	}
	return &Server{
		version:           byte(version),
		username:          username,
		passwd:            passwd,
		deadline:          deadline,
		supportAuthMethod: supportAuthMethod,
	}
}

// Listen 监听
func (s *Server) Listen(addr, port string) (err error) {
	if s.conn == nil {
		s.conn = protocol.New()
	}

	if err = s.conn.Listen(addr + ":" + port); err == nil {
		for {
			conn, err := s.conn.Accept()
			if err != nil {
				log.Error("[server.Listen] accept err: ", err)
				continue
			}
			if err = conn.SetDeadline(time.Now().Add(s.deadline)); err != nil {
				log.Error("[server.Listen] SetDeadline err: ", err, conn.RemoteAddr().String())
				continue
			}
			frame := &Frame{}
			go s.authConn(frame, conn)
		}
	}
	return
}

func (s *Server) checkVersion(version byte) (err error) {
	if version != s.version {
		return fmt.Errorf("<version incorrect, need socks %d>", s.version)
	}
	return
}

// 认证
func (s *Server) authConn(frame *Frame, c protocol.Conn) {
	defer c.Close()

	// 客户端支持的认证方法数
	// +-----+---------------+
	// | VER | METHOD_COUNTS |
	// +-----+---------------+
	// |   1 |             1 |
	// +-----+---------------+
	buff := make([]byte, 2)
	if _, err := c.ReadFull(buff); err != nil {
		log.Error("[authConn] Read header err: ", err, c.RemoteAddr().String())
		return
	}

	if err := s.checkVersion(buff[0]); err != nil {
		log.Error("[authConn] checkVersion err: ", err, c.RemoteAddr().String())
		return
	}

	// methods(由之前method_counts决定)
	// +---------+
	// | METHODS |
	// +---------+
	// | 1-255   |
	// +---------+
	methodCount := buff[1]
	if methodCount > 0 {
		// 读取所有认证方式
		buff = make([]byte, methodCount)
		if _, err := c.ReadFull(buff); err != nil {
			log.Error("[authConn] Read methods err: ", err, c.RemoteAddr().String())
			return
		}
	} else {
		// 不认证
		buff = []byte{AuthNoAuthRequired}
	}

	var chooseAuthMethod byte
	for _, v1 := range s.supportAuthMethod {
		for _, v2 := range buff {
			if v1 == v2 {
				chooseAuthMethod = v1
			}
		}
	}

	if _, err := c.Write(frame.ServerAuthResponse(s.version, chooseAuthMethod)); err != nil {
		log.Error("[authConn] ServerAuthResponse write err: ", err, c.RemoteAddr().String())
		return
	}

	switch chooseAuthMethod {
	case AuthNoAuthRequired:
		// 没有认证 Do Nothing
	case AuthUsernamePasswd:
		// 用户名密码验证
		err := s.authUsernamePasswd(frame, c)
		if err != nil {
			log.Error("[authConn] authUsernamePasswd err: ", err, c.RemoteAddr().String())
			return
		}

	default:
		log.Error("[authConn] unknown auth type ", c.RemoteAddr().String())
		return
	}

	s.handleConn(frame, c)
	return
}

func (s *Server) authUsernamePasswd(frame *Frame, c protocol.Conn) (err error) {
	buff := make([]byte, 2)
	if _, err = c.ReadFull(buff); err != nil {
		return
	}

	if err = s.checkVersion(buff[0]); err != nil {
		return
	}

	var username, passwd []byte
	// 读取username
	unameLen := buff[1]
	if unameLen < 0 {
		return errors.New("<uname length is zero>")
	}

	buff = make([]byte, unameLen)
	if _, err = c.ReadFull(buff); err != nil {
		return
	}
	username = make([]byte, unameLen)
	copy(username, buff)

	// 读取passwd
	buff = make([]byte, 1)
	if _, err = c.ReadFull(buff); err != nil {
		return
	}
	passwdLen := buff[0]
	if passwdLen < 0 {
		return errors.New("<passwd length is zero>")
	}
	buff = make([]byte, passwdLen)
	if _, err = c.ReadFull(buff); err != nil {
		return
	}
	passwd = make([]byte, passwdLen)
	copy(passwd, buff)

	// ServerUsernamePasswdResponse 第二个参数为status > 0 failed, = 0 success
	if s.username == string(username) && s.passwd == string(passwd) {
		if _, err := c.Write(frame.ServerUsernamePasswdResponse(s.version, 0)); err != nil {
			return fmt.Errorf("<Write error> %w", err)
		}
		return nil
	}

	if _, err = c.Write(frame.ServerUsernamePasswdResponse(s.version, 100)); err != nil {
		return fmt.Errorf("<Write error> %w", err)
	}
	return errors.New("<username/passwd dismatch>")
}

// 处理command
func (s *Server) handleConn(frame *Frame, c protocol.Conn) {
	// +-----+---------+-----+
	// | VER | COMMAND | RSV |
	// +-----+---------+-----+
	// |   1 |       1 |   1 |
	// +-----+---------+-----+
	buff := make([]byte, 3)
	if _, err := c.ReadFull(buff); err != nil {
		log.Error("[handleConn] read err: ", err, c.RemoteAddr().String())
		return
	}

	if err := s.checkVersion(buff[0]); err != nil {
		log.Error("[handleConn] checkVersion err: ", err, c.RemoteAddr().String())
		return
	}

	switch buff[1] {
	case CmdConnect:
		s.doConnect(frame, c)
	case CmdBind:
		fallthrough
	case CmdUDP:
		fallthrough
	default:
		if _, err := c.Write(frame.ServerCommandResponse(s.version, ReplyCommandNotSupport, byte(0), "", "")); err != nil {
			log.Error("[handleConn] CommandNotSupport ", err, c.RemoteAddr().String())
		}
	}
}

// 返回响应
// +---------+----------+-----+--------------+----------+----------+
// | VERSION | RESPONSE | RSV | ADDRESS_TYPE | BND.ADDR | BND.PORT |
// +---------+----------+-----+--------------+----------+----------+
// |       1 |        1 |   1 |            1 | 1-255    |        2 |
// +---------+----------+-----+--------------+----------+----------+
func (s *Server) doConnect(frame *Frame, c protocol.Conn) {
	addr, port, err := ReadAddress(c)
	if err != nil {
		log.Error("[doConnect] ReadAddress ", err, c.RemoteAddr().String())
		return
	}

	// 连接目标服务器
	var dst net.Conn
	if dst, err = net.Dial("tcp", addr+":"+port); err != nil {
		log.Error("[doConnect] Dail err: ", err, c.RemoteAddr().String())
		if _, err = c.Write(frame.ServerCommandResponse(s.version, ReplyNetworkUnreachable, byte(0), "", "")); err != nil {
			log.Error("[doConnect] ServerCommandResponse err: ", err, c.RemoteAddr().String())
		}
		return
	}

	// 本机的外网IP
	bindIP := s.getExternalIP()
	if bindIP == "" {
		return
	}
	bindPort := strings.Split(dst.LocalAddr().String(), ":")[1]
	// 开启端口转发监听 等待客户端连接
	serv := protocol.New()
	if err = serv.Listen(bindIP + ":" + bindPort); err != nil {
		log.Error("[doConnect] listen err: ", err)
	}
	defer serv.Close()

	// 响应客户端command数据包
	if _, err = c.Write(frame.ServerCommandResponse(s.version, ReplySuccess, byte(0), bindIP, bindPort)); err != nil {
		log.Error("[doConnect] ServerCommandResponse err: ", err, c.RemoteAddr().String())
		return
	}

	// 转发端口流量
	for {
		src, err := serv.Accept()
		if err != nil {
			log.Error("[doConnect] proxy port accept err: ", err)
			break
		}
		// log.Info("from: ", src.RemoteAddr().String(), " to: ", dst.RemoteAddr().String())

		// 只接受一个tcp连接
		s.proxy(dst, src)
		return
	}

	if _, err = c.Write(frame.ServerCommandResponse(s.version, ReplySOCKSServerFailure, byte(0), "", "")); err != nil {
		log.Error("[doConnect] ServerCommandResponse err: ", err, c.RemoteAddr().String())
		return
	}
	return
}

func (s *Server) doBind(c protocol.Conn) (err error) {
	return
}
func (s *Server) doUDP(c protocol.Conn) (err error) {
	return
}

func (s *Server) proxy(s1 net.Conn, s2 protocol.Conn) {
	defer s1.Close()
	defer s2.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			_, err := io.Copy(s1, s2)
			if err != nil {
				log.Error("[proxy] dst to src err: ", err)
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			_, err := io.Copy(s2, s1)
			if err != nil {
				log.Error("[proxy] src to dst err: ", err)
				break
			}
		}
	}()

	wg.Wait()

	return
}

func (s *Server) getLocalIP() (ip string) {
	ip = s.getExternalIP()
	if ip != "" {
		return
	}
	return s.getInternalIP()
}

func (s *Server) getExternalIP() (ip string) {
	conn, err := net.DialTimeout("udp", "www.baidu.com:80", time.Second*1)
	if err != nil {
		log.Error("[server.getExternalIP]", err)
		return
	}
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0]
}

func (s *Server) getInternalIP() (ip string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("[server.getInternalIP", err)
		return
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
				return
			}
		}
	}
	return
}
