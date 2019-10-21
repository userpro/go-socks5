package protocol

import (
	"io"
	"net"
	"time"
)

// Conn 连接接口
type Conn interface {
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	SetReadTimeout(timeout time.Duration)
	SetWriteTimeout(timeout time.Duration)

	Dial(addr string) (err error)
	Write(data []byte) (nwrite int, err error)
	Read(buff []byte) (nread int, err error)
	ReadFull(buff []byte) (nread int, err error)
	Close() error

	Accept() (c Conn, err error)
	Listen(args ...interface{}) (err error)
}

// Stream 流
type Stream interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
}
