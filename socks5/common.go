package socks5

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

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
