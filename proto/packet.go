package proto

import (
	"encoding/binary"
	"time"

	"github.com/mikonova/relayproto/types"
)

var Signature = [4]byte{42, 34, 204, 149}

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
	return
}

// Encode data to binary format ready for sending
func (ipPacket IpPacket) Encode() (packet []byte) {
	packet = make([]byte, 0)
	packet = append(packet, ipPacket.PacketType)
	binary.BigEndian.AppendUint16(packet, ipPacket.IpStringLength)
	packet = append(packet, []byte(ipPacket.IpString)...)
	return
}

// A unified decoding function, which returns IpPacket, MessagePacket or nil (in case of an invalid type).
// A valid type, being not the message will return the IpPacket with the type within the binary.
func Decode(packet []byte) (p Packet) {
	switch packet[0] {
	case types.IpCarrier:
		return IpPacket{
			PacketType:     types.IpCarrier,
			IpStringLength: binary.BigEndian.Uint16(packet[1:3]),
			IpString:       string(packet[3:]),
		}
	default:
		if packet[0] > types.OnReceiveFail {
			println("packet didn't pass the inspection - unknown type")
			return nil
		} else if packet[0] != types.Message {
			return IpPacket{
				PacketType: packet[0],
			}
		}
		msgPacket := MessagePacket{
			PacketType: packet[0],
		}
		if packet[1] == 1 {
			msgPacket.IsOutgoung = true
		} else {
			msgPacket.IsOutgoung = false
		}
		var timestamp time.Time
		timelen := binary.BigEndian.Uint16(packet[2:4])
		timestamp.UnmarshalBinary(packet[4 : timelen+4])
		msgPacket.Timestamp = timestamp
		msglen := binary.BigEndian.Uint32(packet[timelen+4 : timelen+4+4])
		msgPacket.MessageLength = msglen
		msgPacket.MessageContent = string(packet[timelen+8 : msglen+uint32(timelen)+8])

		return msgPacket
	}
}
