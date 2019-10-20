package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"socks5/protocol"
	"strconv"
	"strings"
	"sync"
)

var s5Buf sync.Pool

func init() {
	s5Buf.New = func() interface{} {
		return make([]byte, 32768)
	}
}

func handleClient(p1 io.ReadWriteCloser, p2 net.Conn) {
	defer p1.Close()
	defer p2.Close()

	if s1, ok := p1.(protocol.Stream); ok {
		log.Info("stream open in:", s1.RemoteAddr().String(), " out:", p2.RemoteAddr().String())
		defer log.Info("stream close in:", s1.RemoteAddr().String(), " out:", p2.RemoteAddr().String())
	}

	streamCopy := func(dst io.Writer, src io.ReadCloser) chan struct{} {
		die := make(chan struct{})
		go func() {
			buff := s5Buf.Get().([]byte)
			if _, err := io.CopyBuffer(dst, src, buff); err != nil {
				log.Error("[streamCopy] err: ", err)
			}
			s5Buf.Put(buff)
			close(die)
		}()
		return die
	}

	select {
	case <-streamCopy(p1, p2):
	case <-streamCopy(p2, p1):
	}
}

// StrToByteIPv4 字符串转IPv4
func StrToByteIPv4(ipv4 string) []byte {
	var tmp int64
	var err error

	res := make([]byte, 4)
	s := strings.Split(ipv4, ".")
	if len(s) < 4 {
		log.Info("[Str2IPv4] invalid ipv4 format.")
		return nil
	}

	for i := 0; i < 4; i++ {
		tmp, err = strconv.ParseInt(s[i], 10, 8)
		if err != nil {
			log.Info("[Str2IPv4] invalid ipv4 format.")
			return nil
		}
		res[i] = byte(tmp)
	}
	return res
}

// StrToByteIPv6 字符串转IPv6
func StrToByteIPv6(ipv6 string) []byte {
	var tmp int64
	var err error

	res := make([]byte, 16)
	s := strings.Split(ipv6, ":")
	if len(s) < 8 {
		log.Info("[Str2IPv6] invalid ipv6 format.")
		return nil
	}

	for i := 0; i < 16; i++ {
		tmp, err = strconv.ParseInt(s[i], 16, 8)
		if err != nil {
			log.Info("[Str2IPv6] invalid ipv6 format.")
			return nil
		}
		res[i] = byte(tmp)
	}

	return res
}

// IPv4ByteToStr IPv4转字符串
func IPv4ByteToStr(ipv4 []byte) string {
	ipv4Str := ""
	for i := 0; i < 4; i++ {
		ipv4Str += strconv.Itoa(int(ipv4[i])) + "."
	}
	return ipv4Str[:len(ipv4Str)-1]
}

// IPv6ByteToStr IPv6转字符串
func IPv6ByteToStr(ipv6 []byte) string {
	ipv6Str := ""
	for i := 0; i < 16; i++ {
		ipv6Str += fmt.Sprintf("%x", ipv6[i]) + ":"
	}
	return ipv6Str[:len(ipv6Str)-1]
}

// Uint16ToByte uint16转[]byte
func Uint16ToByte(a uint16) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf, a)
	return buf
}

// ByteToUint16 []byte转uint16
func ByteToUint16(a []byte) uint16 {
	return binary.BigEndian.Uint16(a)
}
