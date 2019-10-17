package protocol

import (
	"crypto/sha1"
	"io"
	"net"
	"time"

	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

// KcpConn Kcp连接
type KcpConn struct {
	conn       *kcp.UDPSession
	blockCrypt *kcp.BlockCrypt
	listener   *kcp.Listener
}

// New KcpConn对象
func New() Conn {
	key := pbkdf2.Key([]byte(KCPPasswd), []byte(KCPSalt), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)

	return &KcpConn{
		blockCrypt: &block,
	}
}

// RemoteAddr 返回raw conn
func (s5 *KcpConn) RemoteAddr() net.Addr { return s5.conn.RemoteAddr() }

// LocalAddr 返回raw conn
func (s5 *KcpConn) LocalAddr() net.Addr { return s5.conn.LocalAddr() }

// SetDeadline 设置超时
func (s5 *KcpConn) SetDeadline(deadline time.Time) error { return s5.conn.SetDeadline(deadline) }

// Dial Kcp发起连接
func (s5 *KcpConn) Dial(addr, port string) (err error) {
	sess, err := kcp.DialWithOptions(addr+":"+port, *s5.blockCrypt, 10, 3)
	s5.conn = sess
	return err
}

// Send data
func (s5 *KcpConn) Write(data []byte) (nwrite int, err error) {
	ncount := 0
	for {
		nwrite, err = s5.conn.Write(data)
		if err != nil {
			return
		}
		ncount += nwrite
		if ncount >= len(data) {
			return
		}
	}
}

// Read data
func (s5 *KcpConn) Read(buff []byte) (nread int, err error) {
	return s5.conn.Read(buff)
}

// ReadFull data
func (s5 *KcpConn) ReadFull(buff []byte) (nread int, err error) {
	return io.ReadFull(s5.conn, buff)
}

// Close conn
func (s5 *KcpConn) Close() error {
	return s5.conn.Close()
}

// Accept conn
func (s5 *KcpConn) Accept() (c Conn, err error) {
	sess, err := s5.listener.AcceptKCP()
	return &KcpConn{conn: sess}, err
}

// Listen port
func (s5 *KcpConn) Listen(args ...interface{}) (err error) {
	addr := args[0].(string)
	sess, err := kcp.ListenWithOptions(addr, *s5.blockCrypt, 10, 3)
	s5.listener = sess
	return err
}
