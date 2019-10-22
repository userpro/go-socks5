package protocol

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/segmentio/ksuid"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

// KcpConn Kcp连接
type KcpConn struct {
	sess       *kcpSession            // client
	synConn    map[string]*kcpSession // server
	blockCrypt *kcp.BlockCrypt
	listener   *kcp.Listener

	readTimeout, writeTimeout time.Duration
	pingInterval, pongTimeout time.Duration
}

type kcpSession struct {
	sid                string
	dataConn, keepConn *kcp.UDPSession
}

// New KcpConn对象
func New() Conn {
	key := pbkdf2.Key([]byte(KCPPasswd), []byte(KCPSalt), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)

	return &KcpConn{
		blockCrypt:   &block,
		readTimeout:  time.Second * 3,
		writeTimeout: time.Second * 3,
		pingInterval: time.Second * 3,
		pongTimeout:  time.Second * 3,
	}
}

// SetReadTimeout 设置read timeout
func (s5 *KcpConn) SetReadTimeout(timeout time.Duration) { s5.readTimeout = timeout }

// SetWriteTimeout 设置write timeout
func (s5 *KcpConn) SetWriteTimeout(timeout time.Duration) { s5.writeTimeout = timeout }

// RemoteAddr 返回raw conn
func (s5 *KcpConn) RemoteAddr() net.Addr { return s5.sess.dataConn.RemoteAddr() }

// LocalAddr 返回raw conn
func (s5 *KcpConn) LocalAddr() net.Addr { return s5.sess.dataConn.LocalAddr() }

func (s5 *KcpConn) internalSetWriteTimeout() (err error) {
	if s5.writeTimeout > 0 {
		if err = s5.sess.dataConn.SetWriteDeadline(time.Now().Add(s5.writeTimeout)); err != nil {
			return
		}
	} else if s5.writeTimeout == 0 {
		if err = s5.sess.dataConn.SetWriteDeadline(time.Time{}); err != nil {
			return
		}
	}
	return
}

func (s5 *KcpConn) internalSetReadTimeout() (err error) {
	if s5.readTimeout > 0 {
		if err = s5.sess.dataConn.SetReadDeadline(time.Now().Add(s5.readTimeout)); err != nil {
			return
		}
	} else if s5.readTimeout == 0 {
		if err = s5.sess.dataConn.SetReadDeadline(time.Time{}); err != nil {
			return
		}
	}
	return
}

// Dial Kcp发起连接
// +--------------+------------+
// |     TYPE     | SESSION_ID |
// +--------------+------------+
// | 1(0x00/0x01) |         20 |
// +--------------+------------+
func (s5 *KcpConn) Dial(addr string) (err error) {
	sid := ksuid.New().Bytes()

	dataConn, err := kcp.DialWithOptions(addr, *s5.blockCrypt, 10, 3)
	if err != nil {
		err = fmt.Errorf("<[Dial]%s -> %s %w>", dataConn.RemoteAddr().String(), dataConn.LocalAddr().String(), err)
		return
	}
	dataConn.SetStreamMode(true)
	dataConn.SetWriteDelay(false)

	if _, err = dataConn.Write(append([]byte{0x00}, sid...)); err != nil {
		err = fmt.Errorf("<[Dial]%s -> %s %w>", dataConn.RemoteAddr().String(), dataConn.LocalAddr().String(), err)
		return
	}

	keepConn, err := kcp.DialWithOptions(addr, *s5.blockCrypt, 10, 3)
	if err != nil {
		err = fmt.Errorf("<[Dial]%s -> %s %w>", keepConn.RemoteAddr().String(), keepConn.LocalAddr().String(), err)
		return
	}
	keepConn.SetStreamMode(true)
	keepConn.SetWriteDelay(false)
	if _, err = keepConn.Write(append([]byte{0x01}, sid...)); err != nil {
		err = fmt.Errorf("<[Dial]%s -> %s %w>", keepConn.RemoteAddr().String(), keepConn.LocalAddr().String(), err)
		return
	}

	// ping
	go func() {
		defer s5.Close()
		t := time.NewTicker(s5.pingInterval)
		defer t.Stop()

		var err error
		var nwrite int
		var buff [1]byte
		for {
			<-t.C

			for {
				if err = keepConn.SetWriteDeadline(time.Now().Add(s5.pingInterval)); err != nil {
					return
				}
				if nwrite, err = keepConn.Write([]byte{0x01}); err != nil {
					return
				}
				if nwrite > 0 {
					break
				}
			}
			if err = keepConn.SetReadDeadline(time.Now().Add(s5.pingInterval + s5.pongTimeout)); err != nil {
				return
			}
			if _, err = io.ReadFull(keepConn, buff[:]); err != nil {
				return
			}

		}
	}()

	s5.sess = &kcpSession{
		dataConn: dataConn,
		keepConn: keepConn,
	}
	return err
}

// Send data
func (s5 *KcpConn) Write(data []byte) (nwrite int, err error) {
	ncount := 0
	for {
		if err = s5.internalSetWriteTimeout(); err != nil {
			return
		}

		nwrite, err = s5.sess.dataConn.Write(data)
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
	if err = s5.internalSetReadTimeout(); err != nil {
		return
	}
	return s5.sess.dataConn.Read(buff)
}

// ReadFull data
func (s5 *KcpConn) ReadFull(buff []byte) (nread int, err error) {
	if err = s5.internalSetReadTimeout(); err != nil {
		return
	}
	return io.ReadFull(s5.sess.dataConn, buff)
}

// Close conn
func (s5 *KcpConn) Close() error {
	if s5.listener != nil {
		return s5.listener.Close()
	}
	s5.sess.keepConn.Close()
	return s5.sess.dataConn.Close()
}

// Accept conn
func (s5 *KcpConn) Accept() (c Conn, err error) {
	for {
		var s *kcp.UDPSession
		s, err = s5.listener.AcceptKCP()

		var rbuff [21]byte
		if err = s.SetReadDeadline(time.Now().Add(s5.readTimeout)); err != nil {
			err = fmt.Errorf("<[Accept] %s -> %s %w>", s.RemoteAddr().String(), s.LocalAddr().String(), err)
			s.Close()
			return
		}
		if _, err = io.ReadFull(s, rbuff[:]); err != nil {
			err = fmt.Errorf("<[Accept] %s -> %s %w>", s.RemoteAddr().String(), s.LocalAddr().String(), err)
			s.Close()
			return
		}

		kid := ksuid.New()
		if err = kid.UnmarshalBinary(rbuff[1:]); err != nil {
			err = fmt.Errorf("<[Accept] %s -> %s %w>", s.RemoteAddr().String(), s.LocalAddr().String(), err)
			s.Close()
			return
		}
		sid := kid.String()

		sess, ok := s5.synConn[sid]
		if !ok {
			sess = &kcpSession{}
		}
		if rbuff[0] == byte(0x00) {
			if sess.dataConn != nil {
				sess.dataConn.Close()
			}
			sess.dataConn = s
		} else if rbuff[0] == byte(0x01) {
			if sess.keepConn != nil {
				sess.keepConn.Close()
			}
			sess.keepConn = s
		}
		s5.synConn[sid] = sess

		if sess.dataConn != nil && sess.keepConn != nil {
			sess.dataConn.SetStreamMode(true)
			sess.dataConn.SetWriteDelay(false)
			sess.keepConn.SetStreamMode(true)
			sess.keepConn.SetWriteDelay(false)

			delete(s5.synConn, sess.sid)

			c = New()
			k := c.(*KcpConn)
			k.sess = sess
			// pong
			go func() {
				defer c.Close()

				var buff [1]byte
				var nwrite int
				for {
					if err = k.sess.keepConn.SetReadDeadline(time.Now().Add(s5.pingInterval + s5.pongTimeout)); err != nil {
						return
					}
					if _, err = io.ReadFull(k.sess.keepConn, buff[:]); err != nil {
						return
					}

					for {
						if err = k.sess.keepConn.SetWriteDeadline(time.Now().Add(s5.pingInterval + s5.pongTimeout)); err != nil {
							return
						}
						if nwrite, err = k.sess.keepConn.Write(buff[:]); err != nil {
							return
						}
						if nwrite > 0 {
							break
						}
					}
				}
			}()
			return
		}
	}
}

// Listen port
func (s5 *KcpConn) Listen(args ...interface{}) (err error) {
	addr := args[0].(string)
	sess, err := kcp.ListenWithOptions(addr, *s5.blockCrypt, 10, 3)
	s5.listener = sess
	s5.synConn = make(map[string]*kcpSession)
	return err
}
