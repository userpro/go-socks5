package protocol

import (
	"net"
	"time"
)

// Conn 连接接口
type Conn interface {
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error

	Dial(addr, port string) (err error)
	Write(data []byte) (nwrite int, err error)
	Read(buff []byte) (nread int, err error)
	ReadFull(buff []byte) (nread int, err error)
	Close() error

	Accept() (c Conn, err error)
	Listen(args ...interface{}) (err error)
}
