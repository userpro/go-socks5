package protocol

import (
	"crypto/sha1"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/segmentio/ksuid"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

// KcpConn Kcp连接
type KcpConn struct {
	sess       *kcpSession            // client
	servlock   sync.Mutex             // server
	server     map[string]*kcpSession // server
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
		log.Println(dataConn.RemoteAddr().String(), " -> ", dataConn.LocalAddr().String(), "[Dial] DialWithOptions err: ", err)
		return
	}
	dataConn.SetStreamMode(true)
	dataConn.SetWriteDelay(false)

	if _, err = dataConn.Write(append([]byte{0x00}, sid...)); err != nil {
		log.Println(dataConn.RemoteAddr().String(), " -> ", dataConn.LocalAddr().String(), "[Dial] dataConn Write err: ", err)
		return
	}

	keepConn, err := kcp.DialWithOptions(addr, *s5.blockCrypt, 10, 3)
	if err != nil {
		log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] DialWithOptions err: ", err)
		return
	}
	keepConn.SetStreamMode(true)
	keepConn.SetWriteDelay(false)
	if _, err = keepConn.Write(append([]byte{0x01}, sid...)); err != nil {
		log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] keepConn Write err: ", err)
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
					log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] keepConn SetWriteDeadline err: ", err)
					return
				}
				if nwrite, err = keepConn.Write([]byte{0x01}); err != nil {
					log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] keepConn Write err: ", err)
					return
				}
				if nwrite > 0 {
					break
				}
			}
			log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "ping")

			if err = keepConn.SetReadDeadline(time.Now().Add(s5.pingInterval + s5.pongTimeout)); err != nil {
				log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] keepConn SetReadDeadline err: ", err)
				return
			}
			if _, err = io.ReadFull(keepConn, buff[:]); err != nil {
				log.Println(keepConn.RemoteAddr().String(), " -> ", keepConn.LocalAddr().String(), "[Dial] keepConn ReadFull err: ", err)
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
	defer func() {
		if c == nil {
			log.Println("[Accept] c == nil")
			return
		}
		k := c.(*KcpConn)
		log.Println(k.RemoteAddr().String(), " -> ", k.LocalAddr().String(), "[Accept] accept ")
	}()

	for {
		var s *kcp.UDPSession
		s, err = s5.listener.AcceptKCP()

		var rbuff [21]byte
		if err = s.SetReadDeadline(time.Now().Add(s5.readTimeout)); err != nil {
			log.Println(s.RemoteAddr().String(), " -> ", s.LocalAddr().String(), "[Accept.SetReadDeadline] err: ", err)
			s.Close()
			return
		}
		if _, err = io.ReadFull(s, rbuff[:]); err != nil {
			log.Println(s.RemoteAddr().String(), " -> ", s.LocalAddr().String(), "[Accept.ReadFull] err: ", err)
			s.Close()
			return
		}

		kid := ksuid.New()
		if err = kid.UnmarshalBinary(rbuff[1:]); err != nil {
			log.Println(s.RemoteAddr().String(), " -> ", s.LocalAddr().String(), "[Accept.UnmarshalBinary] err: ", err)
			s.Close()
			return
		}
		sid := kid.String()

		sess, ok := s5.server[sid]
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
		s5.server[sid] = sess

		if sess.dataConn != nil && sess.keepConn != nil {
			sess.dataConn.SetStreamMode(true)
			sess.dataConn.SetWriteDelay(false)
			sess.keepConn.SetStreamMode(true)
			sess.keepConn.SetWriteDelay(false)

			delete(s5.server, sess.sid)

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
						log.Println(k.sess.keepConn.RemoteAddr().String(), " -> ", k.sess.keepConn.LocalAddr().String(), "[Accept.SetReadDeadline] keepConn err: ", err)
						return
					}
					if _, err = io.ReadFull(k.sess.keepConn, buff[:]); err != nil {
						log.Println(k.sess.keepConn.RemoteAddr().String(), " -> ", k.sess.keepConn.LocalAddr().String(), "[Accept.ReadFull] keepConn err: ", err)
						return
					}

					for {
						if err = k.sess.keepConn.SetWriteDeadline(time.Now().Add(s5.pingInterval + s5.pongTimeout)); err != nil {
							log.Println(k.sess.keepConn.RemoteAddr().String(), " -> ", k.sess.keepConn.LocalAddr().String(), "[Accept.SetWriteDeadline] keepConn err: ", err)
							return
						}
						if nwrite, err = k.sess.keepConn.Write(buff[:]); err != nil {
							log.Println(k.sess.keepConn.RemoteAddr().String(), " -> ", k.sess.keepConn.LocalAddr().String(), " [Accept.Write] keepConn err: ", err)
							return
						}
						if nwrite > 0 {
							break
						}
					}
					log.Println(k.sess.keepConn.RemoteAddr().String(), " -> ", k.sess.keepConn.LocalAddr().String(), "pong")
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
	s5.server = make(map[string]*kcpSession)
	return err
}
