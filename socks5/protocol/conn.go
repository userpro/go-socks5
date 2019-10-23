package protocol

import (
	"io"
	"net"
	"time"
)

// Conn 通用Conn
type Conn interface {
	CommonConn
	Dial(addr string) (err error)
	Accept() (c Conn, err error)
	Listen(args ...interface{}) (err error)
}

// CommonConn 连接接口
type CommonConn interface {
	SetReadTimeout(timeout time.Duration)
	SetWriteTimeout(timeout time.Duration)
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	io.ReadWriteCloser
}

// ClientConn 客户端接口
type ClientConn interface {
	CommonConn
	Dial(addr string) (err error)
}

// ServerConn 服务端接口
type ServerConn interface {
	CommonConn
	Accept() (c Conn, err error)
	Listen(args ...interface{}) (err error)
}

// Stream 流
type Stream interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
}
