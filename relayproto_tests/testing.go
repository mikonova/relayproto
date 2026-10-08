package relayproto_tests

import (
	"testing"
	"time"

	"github.com/mikonova/relayproto/proto"
	"github.com/mikonova/relayproto/proto/server"
	"github.com/mikonova/relayproto/types"
)

func AllocsTest() {

	RUNS := 1000

	allocMap := make(map[string]float64)
	println("benchmark has started")
	buf := [20]byte{}
	testIpBuf := [16]byte{}

	pack := proto.NewMessagePacket("testMessage", true, time.Now(), testIpBuf[:])
	iCarrier := proto.NewIpPacket(testIpBuf[:])
	var sig proto.SignalingPacket = types.ServerHello
	packet := pack.Encode()
	ipPack := iCarrier.Encode()

	allocMap["GetIp_Message"] = testing.AllocsPerRun(RUNS, func() {
		_, _ = server.GetIp(packet, &buf)
	})
	allocMap["GetIp_Ip"] = testing.AllocsPerRun(RUNS, func() {
		_, _ = server.GetIp(ipPack, &buf)
	})
	allocMap["NewMessagePacket"] = testing.AllocsPerRun(RUNS, func() {
		_ = proto.NewMessagePacket("test message", true, time.Now(), testIpBuf[:])
	})
	allocMap["NewIpPacket"] = testing.AllocsPerRun(RUNS, func() {
		_ = proto.NewIpPacket(testIpBuf[:])
	})
	allocMap["messagePacket.Encode"] = testing.AllocsPerRun(RUNS, func() {
		_ = pack.Encode()
	})
	allocMap["ipPacket.Encode"] = testing.AllocsPerRun(RUNS, func() {
		_ = iCarrier.Encode()
	})
	allocMap["sig.Encode"] = testing.AllocsPerRun(RUNS, func() {
		_ = sig.Encode(types.ClientConfirmed)
	})
	allocMap["DecodeIP"] = testing.AllocsPerRun(RUNS, func() {
		_, _ = proto.DecodeIP(ipPack)
	})
	allocMap["DecodeMessage"] = testing.AllocsPerRun(RUNS, func() {
		_, _ = proto.DecodeMessage(packet)
	})
	sigPacket := sig.Encode(types.ClientConfirmed)
	allocMap["DecodeSig"] = testing.AllocsPerRun(RUNS, func() {
		_, _ = proto.DecodeSig(sigPacket)
	})
	xorBuf := [8192]byte{}
	allocMap["XorMap"] = testing.AllocsPerRun(RUNS, func() {
		proto.XorMap(sigPacket, &xorBuf)
	})

	for k, v := range allocMap {
		println("function ", k, " avg allocs: ", v)
	}
}
