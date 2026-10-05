package proto

import (
	"encoding/binary"
	"time"

	"github.com/mikonova/relayproto/types"
)

// "magic cookie, aka signature"
var Signature = []byte{42, 34, 204, 149}

// a Unified interface for both IP and Message types
type Packet interface {
	Encode() []byte
}

// A packet for transmitting an IP
type IpPacket struct {
	PacketType     byte
	IpStringLength uint16
	IpString       string
}

// A packet for transmitting a message
type MessagePacket struct {
	PacketType byte
	IsOutgoung bool
	// TimestampLength uint16
	Timestamp      time.Time
	MessageLength  uint32
	MessageContent string
	IpStringLength uint16
	IpString       string
}

// A default constructor for creating a message packet
func NewMessagePacket(message string, isOutgoung bool, timestamp time.Time, IpAddr string) MessagePacket {
	return MessagePacket{
		PacketType:     types.Message,
		IsOutgoung:     isOutgoung,
		Timestamp:      timestamp,
		MessageLength:  uint32(len([]byte(message))),
		MessageContent: message,
		IpString:       IpAddr,
		IpStringLength: uint16(len([]byte(IpAddr))),
	}
}

// A default constructor for creating an IP packet
func NewIpPacket(ipAddr string) IpPacket {
	return IpPacket{
		PacketType:     types.IpCarrier,
		IpStringLength: uint16(len([]byte(ipAddr))),
		IpString:       ipAddr,
	}
}

// Encode data to binary format ready for sending
func (msgPacket MessagePacket) Encode() (packet []byte) {
	packet = make([]byte, 0)
	packet = append(packet, Signature...)
	packet = append(packet, msgPacket.PacketType)
	if msgPacket.IsOutgoung == true {
		packet = append(packet, 1)
	} else {
		packet = append(packet, 0)
	}
	byteTime, err := msgPacket.Timestamp.MarshalBinary()
	if err != nil {
		println("error marshalling the timestamp")
	}

	binary.BigEndian.AppendUint16(packet, uint16(len(byteTime)))
	packet = append(packet, byteTime...)
	binary.BigEndian.AppendUint32(packet, msgPacket.MessageLength)
	packet = append(packet, []byte(msgPacket.MessageContent)...)
	binary.BigEndian.AppendUint16(packet, msgPacket.IpStringLength)
	packet = append(packet, []byte(msgPacket.IpString)...)
	packet = xorMap(packet)
	return
}

// Encode data to binary format ready for sending
func (ipPacket IpPacket) Encode() (packet []byte) {
	packet = make([]byte, 0)
	packet = append(packet, Signature...)
	packet = append(packet, ipPacket.PacketType)
	binary.BigEndian.AppendUint16(packet, ipPacket.IpStringLength)
	packet = append(packet, []byte(ipPacket.IpString)...)
	packet = xorMap(packet)
	return
}

// A unified decoding function, which returns IpPacket, MessagePacket or nil (in case of an invalid type).
// A valid type, being not the message will return the IpPacket with the type within the binary.
func Decode(packet []byte) (p Packet, signature []byte) {
	packet = xorMap(packet)
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
func XorMap(source []byte) (dest []byte) {
	dest = make([]byte, 0)
	for k, v := range source {
		dest = append(dest, v^Signature[k%4])
	}
	return
}
