package server

import (
	"github.com/mikonova/relayproto/proto"
	"github.com/mikonova/relayproto/types"
)

// Get net.IP and a signature from a message or an Ip carrier in the following order
// buf[:16] is an ip and [16:] is a signature. This also return a type of a message in ANY case (even w/ unmatching types)
func GetIp(packet [8192]byte, buf *[20]byte) (packetType byte) {
	ip := (*buf)[0:16]
	sign := (*buf)[16:]
	decodeBuf := [8192]byte{}
	proto.XorMap(packet, &decodeBuf)
	p := decodeBuf[:len(packet)]
	copy(sign, p[:4])
	switch p[4] {
	case types.Message:
		copy(ip, p[6:22])
		return decodeBuf[5]
	case types.IpCarrier:
		copy(ip, p[5:21])
		return decodeBuf[5]
	default:
		println("[WARN] incorrect type in the GetIp() call. Should be Message or IpCarrier")
		return 0xFF
	}
}
