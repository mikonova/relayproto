package proto

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/mikonova/relayproto/types"
)

// "magic cookie, aka signature"
var signature = []byte{42, 34, 204, 149}

type SignalingPacket byte

// A packet for transmitting an IP
type IpPacket struct {
	PacketType byte
	Ip         net.IP
}

// A packet for transmitting a message
type MessagePacket struct {
	PacketType byte
	IsOutgoung bool
	Ip         net.IP
	// TimestampLength uint16
	Timestamp time.Time
	//MessageLength  uint32
	MessageContent string
}

// A default constructor for creating a message packet
func NewMessagePacket(message string, isOutgoung bool, timestamp time.Time, IpAddr net.IP) MessagePacket {
	return MessagePacket{
		PacketType:     types.Message,
		IsOutgoung:     isOutgoung,
		Timestamp:      timestamp,
		MessageContent: message,
		Ip:             IpAddr,
	}
}

// A default constructor for creating an IP packet
func NewIpPacket(ipAddr net.IP) IpPacket {
	return IpPacket{
		PacketType: types.IpCarrier,
		Ip:         ipAddr,
	}
}

// Encode data to binary format ready for sending
func (msgPacket MessagePacket) Encode() (packet []byte) {
	packetArr := [8192]byte{}
	packet = packetArr[0:0]
	packet = append(packet, signature...)
	packet = append(packet, msgPacket.PacketType)
	if msgPacket.IsOutgoung == true {
		packet = append(packet, 1) // 5
	} else {
		packet = append(packet, 0) // 5
	}

	packet = append(packet, msgPacket.Ip...) // 6...21 (22 свободно)
	timeArr := [256]byte{}
	byteTime := timeArr[0:0]
	byteTime, err := msgPacket.Timestamp.AppendBinary(byteTime)
	if err != nil {
		println("error marshalling the timestamp")
	}

	binary.BigEndian.AppendUint16(packet, uint16(len(byteTime))) // 22...23 (24 is free)
	packet = append(packet, byteTime...)

	msgBytesArr := [8192]byte{}
	msgBytes := msgBytesArr[0:0]
	binary.Encode(msgBytes, binary.LittleEndian, msgPacket.MessageContent)
	binary.BigEndian.AppendUint32(packet, uint32(len(msgBytes)))
	packet = append(packet, []byte(msgBytes)...)

	packet = XorMap(packet)

	return
}

// Encode data to binary format ready for sending
func (ipPacket IpPacket) Encode() (packet []byte) {

	packetBuf := [21]byte{}
	packet = packetBuf[0:0]
	packet = append(packet, signature...)
	packet = append(packet, ipPacket.PacketType)
	packet = append(packet, ipPacket.Ip...)
	packet = XorMap(packet)
	return
}

func (sigPacket SignalingPacket) Encode(packetType byte) (packet []byte) {
	packetBuf := [5]byte{}
	packet = packetBuf[0:0]
	packet = append(packet, signature...)
	packet = append(packet, packetType)
	return
}

func DecodeMessage(packet []byte) (msgPacket MessagePacket, sign []byte) {
	packet = XorMap(packet)
	sign = packet[0:4]
	if packet[4] != types.Message {
		panic("[ERR] inorrect packet type")
	}
	msgPacket = MessagePacket{
		PacketType: types.Message,
	}
	if packet[5] == 0 {
		msgPacket.IsOutgoung = true
	} else if packet[5] == 1 {
		msgPacket.IsOutgoung = false
	}
	msgPacket.Ip = packet[6:22]
	timestampLen := binary.BigEndian.Uint16(packet[22:24])
	lenFrame := timestampLen + 24
	msgPacket.Timestamp.UnmarshalBinary(packet[24:lenFrame])
	msglen := binary.BigEndian.Uint32(packet[lenFrame : lenFrame+4])
	binary.Decode(packet[uint32(lenFrame)+4:uint32(lenFrame)+4+msglen], binary.LittleEndian, msgPacket.MessageContent)

	return
}

func DecodeIP(packet []byte) (ipPacket IpPacket, sign []byte) {
	packet = XorMap(packet)
	sign = packet[0:4]
	ipPacket = IpPacket{}
	ipPacket.PacketType = packet[5]
	ipPacket.Ip = packet[6:]
	return
}

// Deprecated: a new version is to be released
func Decode(packet []byte) (p Packet, sign []byte) {
	packet = XorMap(packet)
	switch packet[4] {
	case types.IpCarrier:
		return IpPacket{
			PacketType:     types.IpCarrier,
			IpStringLength: binary.BigEndian.Uint16(packet[4:6]),
			IpString:       string(packet[6:]),
		}, packet[0:4]
	default:
		if packet[0] > types.OnReceiveFail {
			println("packet didn't pass the inspection - unknown type")
			return nil, packet[0:4]
		} else if packet[4] != types.Message {
			return IpPacket{
				PacketType: packet[4],
			}, packet[0:4]
		}
		msgPacket := MessagePacket{
			PacketType: packet[0],
		}
		if packet[5] == 1 {
			msgPacket.IsOutgoung = true
		} else {
			msgPacket.IsOutgoung = false
		}
		var timestamp time.Time
		timelen := binary.BigEndian.Uint16(packet[6:8])
		timestamp.UnmarshalBinary(packet[8 : timelen+8])
		msgPacket.Timestamp = timestamp
		msglen := binary.BigEndian.Uint32(packet[timelen+8 : timelen+8+4])
		msgPacket.MessageLength = msglen
		msgPacket.MessageContent = string(packet[timelen+12 : msglen+uint32(timelen)+12])

		return msgPacket, packet[0:4]
	}
}

// xor map the string with the protocol signature
func XorMap(source []byte) []byte {
	if len(source) >= 8192 {
		println("[ERR] source is too long")
		return nil
	}
	destArr := [8192]byte{}
	dest := destArr[0:0]
	for k, v := range source {
		dest = append(dest, v^signature[k%4])
	}
	copy(source, dest)
	return source
}
