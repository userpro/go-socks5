package protocol

import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/segmentio/ksuid"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"
)

// KcpConfig KCP配置
type KcpConfig struct {
	Key  string
	Salt string
	// "aes", aes-"128", aes-"192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea", "xtea", "xor", "sm4", "none"
	Crypt                                   string
	Mode                                    string
	NoDelay, Interval, Resend, NoCongestion int // 跟随mode
	SndWnd, RcvWnd                          int
	MTU                                     int
	AckNodelay                              bool
	DSCP                                    int
	SockBuf                                 int
	DataShard, ParityShard                  int
}

// KcpConn Kcp连接
type KcpConn struct {
	sess       *kcpSession            // client
	synConn    map[string]*kcpSession // server
	blockCrypt *kcp.BlockCrypt
	listener   *kcp.Listener
	config     *KcpConfig

	readTimeout, writeTimeout time.Duration
	pingInterval, pongTimeout time.Duration
}

type kcpSession struct {
	sid                string
	dataConn, keepConn *kcp.UDPSession
}

func defaultConfig() (config *KcpConfig) {
	return &KcpConfig{
		Key:         "creeper",
		Salt:        "awman",
		Mode:        "fast3",
		MTU:         1400,
		SndWnd:      128,
		RcvWnd:      1024,
		DataShard:   10,
		ParityShard: 3,
		DSCP:        46,
		AckNodelay:  false,
		NoDelay:     1,
		Interval:    40,
		Resend:      2,
		SockBuf:     10240,
	}
}

func combineConfig(c1 *KcpConfig, c2 *KcpConfig) (config *KcpConfig) {
	config = &KcpConfig{}
	if c1.Key == "" {
		config.Key = c2.Key
	}
	if c1.Salt == "" {
		config.Salt = c2.Salt
	}
	if c1.Crypt == "" {
		config.Crypt = c2.Crypt
	}
	if c1.Mode == "" {
		config.Mode = c2.Mode
	}
	if c1.NoDelay == 0 {
		config.NoDelay = c2.NoDelay
	}
	if c1.Interval == 0 {
		config.Interval = c2.Interval
	}
	if c1.Resend == 0 {
		config.Resend = c2.Resend
	}
	if c1.NoCongestion == 0 {
		config.NoCongestion = c2.NoCongestion
	}
	if c1.SndWnd == 0 {
		config.SndWnd = c2.SndWnd
	}
	if c1.RcvWnd == 0 {
		config.RcvWnd = c2.RcvWnd
	}
	if c1.MTU == 0 {
		config.MTU = c2.MTU
	}
	if c1.DSCP == 0 {
		config.DSCP = c2.DSCP
	}
	if c1.SockBuf == 0 {
		config.SockBuf = c2.SockBuf
	}
	if c1.DataShard == 0 {
		config.DataShard = c2.DataShard
	}
	if c1.ParityShard == 0 {
		config.ParityShard = c2.ParityShard
	}
	return
}

// New KcpConn对象
func New(args ...interface{}) Conn {
	var config *KcpConfig
	// 默认参数
	if len(args) <= 0 || args[0] == nil {
		config = defaultConfig()
	} else {
		// 非法参数校验
		var ok bool
		if config, ok = args[0].(*KcpConfig); !ok {
			panic("[protocol.New] args invalid!")
		}
		// 合并默认项
		config = combineConfig(config, defaultConfig())
	}

	pass := pbkdf2.Key([]byte(config.Key), []byte(config.Salt), 4096, 32, sha1.New)
	var block kcp.BlockCrypt
	switch config.Crypt {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}

	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}

	return &KcpConn{
		blockCrypt:   &block,
		config:       config,
		readTimeout:  time.Second * 3,
		writeTimeout: time.Second * 3,
		pingInterval: time.Second * 3,
		pongTimeout:  time.Second * 3,
	}
}

func (s5 *KcpConn) configBaseConn(sess *kcp.UDPSession) {
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(s5.config.NoDelay, s5.config.Interval, s5.config.Resend, s5.config.NoCongestion)
	sess.SetACKNoDelay(s5.config.AckNodelay)
}

// 设置连接windowSize buffer Mtu
func (s5 *KcpConn) configSizeConn(sess *kcp.UDPSession) {
	sess.SetWindowSize(s5.config.SndWnd, s5.config.RcvWnd)
	sess.SetMtu(s5.config.MTU)
	if err := sess.SetDSCP(s5.config.DSCP); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := sess.SetReadBuffer(s5.config.SockBuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := sess.SetWriteBuffer(s5.config.SockBuf); err != nil {
		log.Println("SetWriteBuffer:", err)
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

	dataConn, err := kcp.DialWithOptions(addr, *s5.blockCrypt, s5.config.DataShard, s5.config.ParityShard)
	if err != nil {
		err = fmt.Errorf("<[Dial] %s %w>", addr, err)
		return
	}
	s5.configBaseConn(dataConn)
	s5.configSizeConn(dataConn)

	if _, err = dataConn.Write(append([]byte{0x00}, sid...)); err != nil {
		err = fmt.Errorf("<[Dial] %s -> %s %w>", dataConn.RemoteAddr().String(), dataConn.LocalAddr().String(), err)
		return
	}

	keepConn, err := kcp.DialWithOptions(addr, *s5.blockCrypt, s5.config.DataShard, s5.config.ParityShard)
	if err != nil {
		err = fmt.Errorf("<[Dial] %s -> %s %w>", keepConn.RemoteAddr().String(), keepConn.LocalAddr().String(), err)
		return
	}
	s5.configBaseConn(keepConn)

	if _, err = keepConn.Write(append([]byte{0x01}, sid...)); err != nil {
		err = fmt.Errorf("<[Dial] %s -> %s %w>", keepConn.RemoteAddr().String(), keepConn.LocalAddr().String(), err)
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
	return
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
			delete(s5.synConn, sess.sid)
			c = New(s5.config)
			k := c.(*KcpConn)
			k.sess = sess
			k.configBaseConn(k.sess.dataConn)
			k.sess.keepConn.SetStreamMode(true)
			k.sess.keepConn.SetWriteDelay(false)
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
	lis, err := kcp.ListenWithOptions(addr, *s5.blockCrypt, s5.config.DataShard, s5.config.ParityShard)
	s5.listener = lis
	s5.synConn = make(map[string]*kcpSession)
	return err
}
