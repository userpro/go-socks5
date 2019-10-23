package socks5

import (
	"socks5/protocol"

	"time"
)

// Server socks5 服务端
type Server struct {
	listener                  protocol.ServerConn
	readTimeout, writeTimeout time.Duration

	s5 *S5Protocol
}

// ServerOpts 相关参数
type ServerOpts struct {
	Username, Password        string
	ReadTimeout, WriteTimeout time.Duration
}

// NewServer 创建server
func NewServer() *Server {
	return &Server{
		listener: protocol.New(),
		s5:       NewS5Protocol(),
	}
}

// NewServerWithConn 创建server 已有连接
func NewServerWithConn(conn protocol.ServerConn) *Server {
	return &Server{
		listener: conn,
		s5: &S5Protocol{
			version:           5,
			authMethodSupport: []byte{AuthNoAuthRequired},
		},
	}
}

// NewServerWithOpts 创建server并设置
func NewServerWithOpts(opts *ServerOpts) *Server {
	return NewServer().setOpts(opts)
}

// NewServerConnWithOpts 创建server并设置 已有连接
func NewServerConnWithOpts(conn protocol.ServerConn, opts *ServerOpts) *Server {
	return NewServerWithConn(conn).setOpts(opts)
}

func (s *Server) setOpts(opts *ServerOpts) *Server {
	if opts != nil {
		if opts.Username != "" {
			s.s5.authMethodSupport = append(s.s5.authMethodSupport, AuthUsernamePasswd)
		}
		s.s5.username = opts.Username
		s.s5.password = opts.Password
		s.readTimeout = opts.ReadTimeout
		s.writeTimeout = opts.WriteTimeout
	}
	return s
}

// SetDirectMode direct
func (s *Server) SetDirectMode(direct bool) {
	s.s5.SetDirectMode(direct)
}

// Listen 监听
func (s *Server) Listen(addr string) (err error) {
	if err = s.listener.Listen(addr); err == nil {
		defer s.listener.Close()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				log.Error("[server.Listen] Accept err: ", err)
				continue
			}
			log.Info("[server.Listen] ", conn.RemoteAddr().String(), "->", conn.LocalAddr().String())

			if s.readTimeout >= 0 {
				conn.SetReadTimeout(s.readTimeout)
			}

			if s.writeTimeout >= 0 {
				conn.SetWriteTimeout(s.writeTimeout)
			}

			go s.s5.Server(conn)
		}
	}
	return
}
