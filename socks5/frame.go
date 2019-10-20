package socks5

import (
	"net"
	"strconv"
)

// STATUS
const (
	StatusSuccess byte = 0x01
	StatusFailed  byte = 0x02
)

// METHODS_COUNT METHODS
const (
	AuthNoAuthRequired       byte = 0x00
	AuthGSSAPI               byte = 0x01
	AuthUsernamePasswd       byte = 0x02
	AuthIANAAssigned         byte = 0x03 // to 0x7f
	AuthRSVForPrivateMethods byte = 0x80 // to 0xfe
	AuthNoAcceptMethods      byte = 0xff
)

// COMMAND
const (
	CmdConnect byte = 0x01
	CmdBind    byte = 0x02
	CmdUDP     byte = 0x03
)

// REPLY
const (
	ReplySuccess                     byte = 0x00
	ReplySOCKSServerFailure          byte = 0x01
	ReplyConnectionNotAllowByRuleset byte = 0x02
	ReplyNetworkUnreachable          byte = 0x03
	ReplyHostUnreachable             byte = 0x04
	ReplyConnectionRefused           byte = 0x05
	ReplyTTLExpired                  byte = 0x06
	ReplyCommandNotSupport           byte = 0x07
	ReplyAddressTypeNotSupported     byte = 0x08
	ReplyUnassigned                  byte = 0x09
)

// ReplyMessage
var (
	ReplyMessage = map[byte]string{
		ReplySuccess:                     "Success",
		ReplySOCKSServerFailure:          "SOCKSServerFailure",
		ReplyConnectionNotAllowByRuleset: "ConnectionNotAllowByRuleset",
		ReplyNetworkUnreachable:          "NetworkUnreachable",
		ReplyHostUnreachable:             "HostUnreachable",
		ReplyConnectionRefused:           "ConnectionRefused",
		ReplyTTLExpired:                  "TTLExpired",
		ReplyCommandNotSupport:           "CommandNotSupport",
		ReplyAddressTypeNotSupported:     "AddressTypeNotSupported",
		ReplyUnassigned:                  "Unassigned",
	}
)

// ADDRESS_TYPE
const (
	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x03
	AddrIPv6   byte = 0x04
)

// Frame 最终发送的数据包
type Frame struct {
	data []byte
}

// Init 初始化
func (f *Frame) Init() {
	f.data = []byte{}
}

// Get 返回数据
func (f *Frame) Get() []byte {
	return f.data
}

/* ------------------ client ------------------ */

// ClientAuthRequest 客户端发出认证请求
func (f *Frame) ClientAuthRequest(version byte, methods []byte) []byte {
	f.Init()
	f.wVersion(version)
	f.wMethods(methods)
	return f.Get()
}

// ClientUsernamePasswdRequest 客户端账号密码认证
func (f *Frame) ClientUsernamePasswdRequest(version byte, uname, passwd string) []byte {
	f.Init()
	f.wVersion(version)
	f.wUsername(uname)
	f.wPasswd(passwd)
	return f.Get()
}

// ClientCommandRequest 客户端发送命令
func (f *Frame) ClientCommandRequest(version byte, command, rsv byte, dstAddr, dstPort string) []byte {
	f.Init()
	f.wVersion(version)
	f.wCommand(command)
	f.wRSV(rsv)
	f.wAddress(dstAddr, dstPort)
	return f.Get()
}

/* ------------------ server ------------------ */

// ServerAuthResponse 服务端返回选择的认证方法
func (f *Frame) ServerAuthResponse(version, method byte) []byte {
	f.Init()
	f.wVersion(version)
	f.wMethod(method)
	return f.Get()
}

// ServerUsernamePasswdResponse 服务器返回账号密码认证结果
// status = 0 success, status > 0 failed
func (f *Frame) ServerUsernamePasswdResponse(version byte, status int) []byte {
	f.Init()
	f.wVersion(version)
	f.wStatus(status)
	return f.Get()
}

// ServerCommandResponse 服务端命令执行响应
func (f *Frame) ServerCommandResponse(version, reply, rsv byte, bindAddr string, bindPort string) []byte {
	f.Init()
	f.wVersion(version)
	f.wReply(reply)
	f.wRSV(rsv)
	f.wAddress(bindAddr, bindPort)
	return f.Get()
}

/* ------------------ low methods ------------- */

// VER
func (f *Frame) wVersion(ver byte) { f.data = append(f.data, byte(ver)) }

// ULEN UNAME
func (f *Frame) wUsername(uname string) {
	f.data = append(f.data, byte(len(uname)))
	f.data = append(f.data, []byte(uname)...)
}

// PLLEN PASSWD
func (f *Frame) wPasswd(passwd string) {
	f.data = append(f.data, byte(len(passwd)))
	f.data = append(f.data, []byte(passwd)...)
}

func (f *Frame) wStatus(status int) { f.data = append(f.data, byte(status)) }

func (f *Frame) wMethod(method byte) { f.data = append(f.data, method) }

func (f *Frame) wMethods(methods []byte) {
	if len(methods) > 0 {
		f.data = append(f.data, byte(len(methods)))
		f.data = append(f.data, methods...)
	} else {
		f.data = append(f.data, byte(0))
	}
}

func (f *Frame) wCommand(command byte) { f.data = append(f.data, command) }

// RSV
func (f *Frame) wRSV(rsv byte) { f.data = append(f.data, rsv) }

func (f *Frame) wReply(reply byte) { f.data = append(f.data, reply) }

// +--------------+----------+----------+
// | ADDRESS_TYPE | DST.ADDR | DST.PORT |
// +--------------+----------+----------+
// |            1 | 1-255    |        2 |
// +--------------+----------+----------+
func (f *Frame) wAddress(address, port string) {
	// 不关心地址的数据包
	if len(address) <= 0 {
		address = "0.0.0.0"
	}

	ip := net.ParseIP(address)
	if ip == nil {
		f.data = append(f.data, AddrDomain)
		f.data = append(f.data, byte(len(address)))
		f.data = append(f.data, []byte(address)...)
	} else if ip.To4() != nil {
		f.data = append(f.data, AddrIPv4)
		f.data = append(f.data, ip.To4()...)
	} else if ip.To16() != nil {
		f.data = append(f.data, AddrIPv6)
		f.data = append(f.data, ip.To16()...)
	} else {
		log.Info("[wAddress] invalid address type ")
		return
	}

	if len(port) <= 0 {
		port = "0"
	}
	t, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		log.Info("[wAddress] invalid port ", err)
		return
	}

	f.data = append(f.data, []byte{byte(t >> 8), byte(t)}...)
}
