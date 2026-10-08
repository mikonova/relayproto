package server

import (
	"net"

	"github.com/mikonova/relayproto/proto"
	"github.com/mikonova/relayproto/types"
)

// Get net.IP and a signature from a message or an Ip carrier. Otherwise, get 2 nils.
func GetIp(packet [8192]byte, buf *[20]byte) (ip net.IP, sign []byte) {
	ip = (*buf)[0:16]
	sign = (*buf)[16:]
	decodeBuf := [8192]byte{}
	proto.XorMap(packet, &decodeBuf)
	p := decodeBuf[:len(packet)]
	copy(sign, p[:4])
	switch p[4] {
	case types.Message:
		copy(ip, p[6:22])
		return
	case types.IpCarrier:
		copy(ip, p[5:21])
		return
	default:
		println("[WARN] incorrect type in the GetIp() call. Should be Message or IpCarrier")
		return nil, nil
	}
}
