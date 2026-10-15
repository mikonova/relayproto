package proto

import (
	"encoding/binary"
	"time"

	"github.com/mikonova/relayproto/types"
)

// "magic cookie, aka signature"
var signature = []byte{42, 34, 204, 149}

// type for signals between the server and the client, excluding IdCarrier and Message
type SignalingPacket byte

// A packet for transmitting an ID
type idPacket struct {
	PacketType byte
	Id         [16]byte
}

// A packet for transmitting a message
type messagePacket struct {
	PacketType byte
	IsOutgoung bool
	DestId     [16]byte
	// TimestampLength uint16
	Timestamp time.Time
	//MessageLength  uint32
	MessageContent string
}

// A default constructor for creating a message packet
func NewMessagePacket(message string, isOutgoung bool, timestamp time.Time, id [16]byte) messagePacket {
	return messagePacket{
		PacketType:     types.Message,
		IsOutgoung:     isOutgoung,
		Timestamp:      timestamp,
		MessageContent: message,
		DestId:         id,
	}

}

// A default constructor for creating an ID packet
func NewIdPacket(id [16]byte) idPacket {
	return idPacket{
		PacketType: types.IdCarrier,
		Id:         id,
	}
}

// Create a new byte slice from the object, prepared for sending
func (msgPacket messagePacket) Encode() (packet [8192]byte) {
	packetArr := [8192]byte{}
	p := packetArr[0:0]
	p = append(p, signature...)
	p = append(p, msgPacket.PacketType)
	if msgPacket.IsOutgoung == true {
		p = append(p, 1) // 5
	} else {
		p = append(p, 0) // 5
	}

	p = append(p, msgPacket.DestId[:]...) // 6...21 (22 свободно)
	timeArr := [256]byte{}
	byteTime := timeArr[0:0]
	byteTime, err := msgPacket.Timestamp.AppendBinary(byteTime)
	if err != nil {
		println("[ERR] error marshalling the timestamp")
	}

	p = binary.BigEndian.AppendUint16(p, uint16(len(byteTime))) // 22...23 (24 is free)
	p = append(p, byteTime...)

	p = binary.BigEndian.AppendUint32(p, uint32(len(msgPacket.MessageContent)))
	p = append(p, msgPacket.MessageContent...)
	buf := [8192]byte{}
	XorMap(packetArr, &buf)
	copy(packet[:], buf[:])
	return
}

// Create a new byte slice from the object, prepared for sending
func (iPacket idPacket) Encode() (packet [8192]byte) {

	packetBuf := [21]byte{}
	p := packetBuf[0:0]
	p = append(p, signature...)
	p = append(p, iPacket.PacketType)
	p = append(p, iPacket.Id[:]...)
	buf := [8192]byte{}
	fullPacketBuf := [8192]byte{}
	copy(fullPacketBuf[:], packetBuf[:])
	XorMap(fullPacketBuf, &buf)
	copy(packet[:], buf[:])
	return
}

// Create a new byte slice from the variable, prepared for sending
func (sigPacket SignalingPacket) Encode(packetType byte) (packet [8192]byte) {
	if sigPacket == types.IdCarrier || sigPacket == types.Message {
		println("[WARN] this type ", sigPacket, " shouldn't be in the SignalingPacket")
		return packet
	}
	packetBuf := [5]byte{}
	p := packetBuf[0:0]
	p = append(p, signature...)
	p = append(p, packetType)
	buf := [8192]byte{}
	fullPacketBuf := [8192]byte{}
	copy(fullPacketBuf[:], packetBuf[:])
	XorMap(fullPacketBuf, &buf)
	copy(packet[:], buf[:])
	return
}

// Decode the message packet to get the messagePacket object and the signature
func DecodeMessage(packet [8192]byte) (msgPacket messagePacket, sign [4]byte) {
	buf := [8192]byte{}
	XorMap(packet, &buf)
	p := buf[:len(packet)]
	for v := range 4 {
		sign[v] = p[v]
	}
	if p[4] != types.Message {
		panic("[ERR] inorrect packet type")
	}
	msgPacket = messagePacket{
		PacketType: types.Message,
	}
	switch p[5] {
	case 0:
		msgPacket.IsOutgoung = false
	case 1:
		msgPacket.IsOutgoung = true
	}
	copy(msgPacket.DestId[:], p[6:22])
	timestampLen := binary.BigEndian.Uint16(p[22:24])
	lenFrame := timestampLen + 24
	msgPacket.Timestamp.UnmarshalBinary(p[24:lenFrame])
	msglen := binary.BigEndian.Uint32(p[lenFrame : lenFrame+4])
	msgPacket.MessageContent = string(p[uint32(lenFrame)+4 : uint32(lenFrame)+4+msglen])
	return
}

// Decode the ID packet to get the IDpacket and the signature
func DecodeID(packet [8192]byte) (iPacket idPacket, sign [4]byte) {
	buf := [8192]byte{}
	XorMap(packet, &buf)
	p := buf[:len(packet)]
	for v := range 4 {
		sign[v] = p[v]
	}
	iPacket = idPacket{}
	iPacket.PacketType = p[4]
	copy(iPacket.Id[:], p[5:21])
	return
}

// Decode the signal packet to get the signal and the signature
func DecodeSig(packet [8192]byte) (sigPacket SignalingPacket, sign [4]byte) {
	buf := [8192]byte{}
	XorMap(packet, &buf)
	p := buf[:len(packet)]
	sigPacket = SignalingPacket(p[3])
	for v := range 4 {
		sign[v] = p[v]
	}
	return
}

// XOR map the string with the protocol signature
func XorMap(source [8192]byte, buf *[8192]byte) {
	if len(source) > 8192 {
		println("[ERR] source is too long")
		return
	}
	if len(buf) > 8192 {
		println("[ERR] source is too long")
		return

	}
	//src = 12, 0,1,2,3;4,5,6,7;8,9,10,11
	for i := 0; i <= len(source)-4; i += 4 {
		buf[i] = source[i] ^ signature[0]
		buf[i+1] = source[i+1] ^ signature[1]
		buf[i+2] = source[i+2] ^ signature[2]
		buf[i+3] = source[i+3] ^ signature[3]
	}
}
