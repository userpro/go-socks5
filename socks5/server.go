package socks5

import (
	"socks5/protocol"

	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Server socks5 服务端
type Server struct {
	version                   byte
	listener                  protocol.Conn
	readTimeout, writeTimeout time.Duration

	supportAuthMethod  []byte // 支持的认证方式
	username, password string
}

// ServerOpts 相关参数
type ServerOpts struct {
	Username, Password        string
	ReadTimeout, WriteTimeout time.Duration
}

// NewServer 创建server 默认无timeout
func NewServer() *Server {
	return &Server{
		version:           5,
		listener:          protocol.New(),
		supportAuthMethod: []byte{AuthNoAuthRequired},
	}
}

// NewServerWithTimeout 带超时Server 设置为0 清除timeout
func NewServerWithTimeout(opts *ServerOpts) *Server {
	serv := NewServer()
	if opts.Username != "" {
		serv.supportAuthMethod = append(serv.supportAuthMethod, AuthUsernamePasswd)
	}
	serv.username = opts.Username
	serv.password = opts.Password
	serv.readTimeout = opts.ReadTimeout
	serv.writeTimeout = opts.WriteTimeout
	return serv
}

// Listen 监听
func (s *Server) Listen(addr string) (err error) {
	if err = s.listener.Listen(addr); err == nil {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				log.Error("[server.Listen] accept err: ", err)
				continue
			}

			// log.Info("[Server] ", conn.RemoteAddr().String())

			if s.readTimeout >= 0 {
				conn.SetReadTimeout(s.readTimeout)
			}

			if s.writeTimeout >= 0 {
				conn.SetWriteTimeout(s.writeTimeout)
			}

			frame := &Frame{}
			go s.authConn(frame, conn)
		}
	}
	return
}

func (s *Server) isSameVersion(version byte) (err error) {
	if version != s.version {
		return fmt.Errorf("<version incorrect, need socks %d>", s.version)
	}
	return
}

// 认证
func (s *Server) authConn(frame *Frame, conn protocol.Conn) {
	var totalBuff [256]byte

	// 客户端支持的认证方法数
	// +-----+---------------+
	// | VER | METHOD_COUNTS |
	// +-----+---------------+
	// |   1 |             1 |
	// +-----+---------------+
	buff := totalBuff[:2]
	if _, err := conn.ReadFull(buff); err != nil {
		log.Error("[authConn] Read header err: ", err, "from", conn.RemoteAddr().String())
		return
	}

	if err := s.isSameVersion(buff[0]); err != nil {
		log.Error("[authConn] isSameVersion err: ", err, conn.RemoteAddr().String())
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
		buff = totalBuff[:methodCount]
		if _, err := conn.ReadFull(buff); err != nil {
			log.Error("[authConn] Read methods err: ", err, conn.RemoteAddr().String())
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

	if _, err := conn.Write(frame.ServerAuthResponse(s.version, chooseAuthMethod)); err != nil {
		log.Error("[authConn] ServerAuthResponse write err: ", err, conn.RemoteAddr().String())
		return
	}

	switch chooseAuthMethod {
	case AuthNoAuthRequired:
		// 没有认证 Do Nothing
	case AuthUsernamePasswd:
		// 用户名密码验证
		err := s.authUsernamePasswd(totalBuff[:], frame, conn)
		if err != nil {
			log.Error("[authConn] authUsernamePasswd err: ", err, conn.RemoteAddr().String())
			return
		}

	default:
		log.Error("[authConn] unknown auth type ", conn.RemoteAddr().String())
		return
	}

	s.handleConn(totalBuff[:], frame, conn)
	return
}

// +---------+-----------------+----------+-----------------+----------+
// | VERSION | USERNAME_LENGTH | USERNAME | PASSWORD_LENGTH | PASSWORD |
// +---------+-----------------+----------+-----------------+----------+
// |       1 |               1 | 1-255    |               1 | 1-255    |
// +---------+-----------------+----------+-----------------+----------+
func (s *Server) authUsernamePasswd(totalBuff []byte, frame *Frame, conn protocol.Conn) (err error) {
	buff := totalBuff[:2]
	if _, err = conn.ReadFull(buff); err != nil {
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
	if _, err = conn.ReadFull(buff); err != nil {
		return
	}
	username = make([]byte, unameLen)
	copy(username, buff)

	// 读取passwd
	buff = make([]byte, 1)
	if _, err = conn.ReadFull(buff); err != nil {
		return
	}
	passwdLen := buff[0]
	if passwdLen < 0 {
		return errors.New("<passwd length is zero>")
	}
	buff = totalBuff[:passwdLen]
	if _, err = conn.ReadFull(buff); err != nil {
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
func (s *Server) handleConn(totalBuff []byte, frame *Frame, conn protocol.Conn) {
	// +-----+---------+-----+
	// | VER | COMMAND | RSV |
	// +-----+---------+-----+
	// |   1 |       1 |   1 |
	// +-----+---------+-----+
	buff := totalBuff[:3]
	if _, err := conn.ReadFull(buff); err != nil {
		log.Error("[handleConn] read err: ", err, conn.RemoteAddr().String())
		return
	}

	if err := s.isSameVersion(buff[0]); err != nil {
		log.Error("[handleConn] isSameVersion err: ", err, conn.RemoteAddr().String())
		return
	}

	switch buff[1] {
	case CmdConnect:
		s.doConnect(frame, conn)
	case CmdBind:
		fallthrough
	case CmdUDP:
		fallthrough
	default:
		if _, err := conn.Write(frame.ServerCommandResponse(s.version, ReplyCommandNotSupport, byte(0), "", "")); err != nil {
			log.Error("[handleConn] CommandNotSupport ", err, conn.RemoteAddr().String())
		}
	}
}

// 返回响应
// +---------+----------+-----+--------------+----------+----------+
// | VERSION | RESPONSE | RSV | ADDRESS_TYPE | BND.ADDR | BND.PORT |
// +---------+----------+-----+--------------+----------+----------+
// |       1 |        1 |   1 |            1 | 1-255    |        2 |
// +---------+----------+-----+--------------+----------+----------+
func (s *Server) doConnect(frame *Frame, conn protocol.Conn) {
	addr, port, err := ReadAddress(conn)
	if err != nil {
		log.Error("[doConnect] ReadAddress ", err, "from", conn.RemoteAddr().String())
		return
	}

	// 测试目标是否可达 同时获取一个可用端口
	p2, err := net.Dial("tcp", addr+":"+port)
	if err != nil {
		log.Error("[doConnect] Dail err: ", err, "from", conn.RemoteAddr().String())
		if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplyNetworkUnreachable, byte(0), "", "")); err != nil {
			log.Error("[doConnect] ServerCommandResponse err: ", err, "from", conn.RemoteAddr().String())
		}
		return
	}
	bindIP := "0.0.0.0"
	bindPort := strings.Split(p2.LocalAddr().String(), ":")[1]

	// 开启端口转发监听 等待客户端连接
	server := protocol.New()
	if err = server.Listen(bindIP + ":" + bindPort); err != nil {
		log.Error("[doConnect] listen err: ", err)
		if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplySOCKSServerFailure, byte(0), "", "")); err != nil {
			log.Error("[doConnect] ServerCommandResponse err: ", err, "from", conn.RemoteAddr().String())
		}
		return
	}
	defer server.Close()

	// 响应客户端command数据包
	if _, err = conn.Write(frame.ServerCommandResponse(s.version, ReplySuccess, byte(0), bindIP, bindPort)); err != nil {
		log.Error("[doConnect] ServerCommandResponse err: ", err, "from", conn.RemoteAddr().String())
		return
	}

	// 转发端口流量
	for {
		p1, err := server.Accept()
		if err != nil {
			log.Error("[doConnect] proxy port accept err: ", err)
			break
		}

		handleClient(p1, p2)
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
