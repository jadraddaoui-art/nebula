package iputil

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func Test_CreateRejectPacket(t *testing.T) {
	h := ipv4.Header{
		Len:      20,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 1, // ICMP
	}

	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4}...)

	expectedLen := ipv4.HeaderLen + 8 + h.Len + 4
	out := make([]byte, expectedLen)
	rejectPacket := CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)

	// ICMP with max header len
	h = ipv4.Header{
		Len:      60,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 1, // ICMP
		Options:  make([]byte, 40),
	}

	b, err = h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4, 0, 0, 0, 0}...)

	expectedLen = maxIPv4RejectPacketSize
	out = make([]byte, MaxRejectPacketSize)
	rejectPacket = CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)

	// TCP with max header len
	h = ipv4.Header{
		Len:      60,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 6, // TCP
		Options:  make([]byte, 40),
	}

	b, err = h.Marshal()
	if err != nil {
		t.Fatalf("h.Marhshal: %v", err)
	}
	b = append(b, []byte{0, 3, 0, 4}...)
	b = append(b, make([]byte, 16)...)

	expectedLen = ipv4.HeaderLen + 20
	out = make([]byte, expectedLen)
	rejectPacket = CreateRejectPacket(b, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, expectedLen)
}

func Test_CreateRejectPacket_NoFragment(t *testing.T) {
	out := make([]byte, MaxRejectPacketSize)

	// IPv4: non-zero fragment offset should not generate reject packet
	h := ipv4.Header{
		Len:      20,
		Src:      net.IPv4(10, 0, 0, 1),
		Dst:      net.IPv4(10, 0, 0, 2),
		Protocol: 17, // UDP
	}
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("h.Marshal: %v", err)
	}
	b = append(b, make([]byte, 8)...)
	// Set fragment offset to non-zero (byte 6-7, offset in 8-byte units)
	b[6] = 0x00
	b[7] = 0x01
	assert.Nil(t, CreateRejectPacket(b, out))

	// MF flag with zero offset (first fragment) should still generate reject
	b[6] = 0x20 // MF flag set
	b[7] = 0x00
	assert.NotNil(t, CreateRejectPacket(b, out))

	// Non-fragment should still generate reject packet
	b[6] = 0x00
	b[7] = 0x00
	assert.NotNil(t, CreateRejectPacket(b, out))

	// DF flag only (not a fragment) should still generate reject packet
	b[6] = 0x40
	b[7] = 0x00
	assert.NotNil(t, CreateRejectPacket(b, out))
}

func Test_CreateRejectPacketIPv6_NoFragment(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")
	out := make([]byte, MaxRejectPacketSize)

	// IPv6 with Fragment header and non-zero offset should not generate reject
	fragHeader := []byte{
		17,   // next header: UDP
		0,    // reserved
		0, 9, // fragment offset=1 (shifted left 3), M=1
		0, 0, 0, 1, // identification
	}
	udpPayload := make([]byte, 8)
	payload := append(fragHeader, udpPayload...)
	packet := makeIPv6Packet(src, dst, 44, payload) // next header 44 = Fragment
	assert.Nil(t, CreateRejectPacket(packet, out))

	// Fragment header with zero offset (first fragment) should still generate reject
	fragHeader[2] = 0
	fragHeader[3] = 1 // offset=0, M=1
	payload = append(fragHeader, udpPayload...)
	packet = makeIPv6Packet(src, dst, 44, payload)
	assert.NotNil(t, CreateRejectPacket(packet, out))
}

func Test_CreateRejectPacket_NoICMPError(t *testing.T) {
	out := make([]byte, MaxRejectPacketSize)

	// ICMP error types should not generate reject packets
	icmpErrorTypes := []byte{3, 4, 5, 11, 12}
	for _, icmpType := range icmpErrorTypes {
		h := ipv4.Header{
			Len:      20,
			Src:      net.IPv4(10, 0, 0, 1),
			Dst:      net.IPv4(10, 0, 0, 2),
			Protocol: 1, // ICMP
		}

		b, err := h.Marshal()
		if err != nil {
			t.Fatalf("h.Marshal: %v", err)
		}
		b = append(b, icmpType, 0, 0, 0, 0, 0, 0, 0)

		rejectPacket := CreateRejectPacket(b, out)
		assert.Nil(t, rejectPacket, "ICMP type %d should not generate a reject packet", icmpType)
	}

	// ICMP non-error types should still generate reject packets
	icmpNonErrorTypes := []byte{0, 8, 13, 14}
	for _, icmpType := range icmpNonErrorTypes {
		h := ipv4.Header{
			Len:      20,
			Src:      net.IPv4(10, 0, 0, 1),
			Dst:      net.IPv4(10, 0, 0, 2),
			Protocol: 1, // ICMP
		}

		b, err := h.Marshal()
		if err != nil {
			t.Fatalf("h.Marshal: %v", err)
		}
		b = append(b, icmpType, 0, 0, 0, 0, 0, 0, 0)

		rejectPacket := CreateRejectPacket(b, out)
		assert.NotNil(t, rejectPacket, "ICMP type %d should generate a reject packet", icmpType)
	}
}

// Test_CreateRejectPacket_RespectsCap ensures it is impossible for
// an oversized ICMPv6 reject to overwrite the neighbor segment's bytes.
func Test_CreateRejectPacket_RespectsCap(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// Inner IPv6 UDP packet. An ICMPv6 reject copies the whole inner packet
	// plus a 48-byte header (40 IPv6 + 8 ICMPv6), so it needs 48 more bytes
	// than the inner packet length.
	inner := makeIPv6Packet(src, dst, 17, make([]byte, 20))

	// The ciphertext scratch reused as the reject buffer is the received
	// datagram: 16-byte Nebula header + inner + 16-byte AEAD tag. That is only
	// 32 bytes of slack, so a full ICMPv6 reject overruns it by 16 bytes.
	const nebulaOverhead = 32
	segLen := len(inner) + nebulaOverhead

	// Shared backing row laid out as [segment][neighbor's 16-byte Nebula header].
	const neighborHdr = 16
	sentinel := bytes.Repeat([]byte{0xAB}, neighborHdr)

	// Uncapped: the slice's capacity reaches into the neighbor, reproducing
	// the overrun that silently drops the neighbor packet.
	backing := make([]byte, segLen+neighborHdr)
	copy(backing[segLen:], sentinel)
	reject := CreateRejectPacket(inner, backing[:segLen])
	assert.NotNil(t, reject, "uncapped buffer reaches into the neighbor, so the reject is built")
	assert.NotEqual(t, sentinel, backing[segLen:segLen+neighborHdr],
		"without the cap the oversized reject overruns into the neighbor segment")

	// Capped (the fix): cap==len, so the builder cannot exceed the segment. The
	// reject does not fit, so it is refused rather than corrupting the neighbor.
	backing = make([]byte, segLen+neighborHdr)
	copy(backing[segLen:], sentinel)
	reject = CreateRejectPacket(inner, backing[:segLen:segLen])
	assert.Nil(t, reject, "capped segment is 16 bytes too small for a full ICMPv6 reject, so it is refused")
	assert.Equal(t, sentinel, backing[segLen:segLen+neighborHdr],
		"capped segment must leave the neighbor untouched")
}

func makeIPv6Packet(src, dst net.IP, nextHeader uint8, payload []byte) []byte {
	b := make([]byte, ipv6.HeaderLen+len(payload))
	b[0] = ipv6.Version << 4
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = nextHeader
	b[7] = 64
	copy(b[8:24], src.To16())
	copy(b[24:40], dst.To16())
	copy(b[ipv6.HeaderLen:], payload)
	return b
}

func Test_CreateRejectPacketIPv6_ICMP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// Small UDP packet: entire original included in body
	udpPayload := make([]byte, 20)
	udpPayload[0] = 0x00 // src port high
	udpPayload[1] = 0x50 // src port low (80)
	udpPayload[2] = 0x01 // dst port high
	udpPayload[3] = 0xBB // dst port low (443)
	packet := makeIPv6Packet(src, dst, 17, udpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Small packet fits entirely: 40 (ipv6 hdr) + 8 (icmpv6 hdr) + 60 (original)
	expectedLen := ipv6.HeaderLen + 8 + len(packet)
	assert.Len(t, rejectPacket, expectedLen)

	// Verify version
	assert.Equal(t, byte(ipv6.Version<<4), rejectPacket[0]&0xf0)
	// Verify next header is ICMPv6 (58)
	assert.Equal(t, byte(58), rejectPacket[6])
	// Verify src/dst are swapped
	assert.Equal(t, dst.To16(), net.IP(rejectPacket[8:24]))
	assert.Equal(t, src.To16(), net.IP(rejectPacket[24:40]))
	// Verify ICMPv6 type=1 (Dest Unreachable), code=1 (Administratively prohibited)
	assert.Equal(t, byte(1), rejectPacket[ipv6.HeaderLen])
	assert.Equal(t, byte(1), rejectPacket[ipv6.HeaderLen+1])
	// Verify entire original packet is included in body
	assert.Equal(t, packet, rejectPacket[ipv6.HeaderLen+8:])

	// Large packet: body is truncated to 1000 bytes
	largePkt := makeIPv6Packet(src, dst, 17, make([]byte, 1200))
	rejectPacket = CreateRejectPacket(largePkt, out)
	assert.NotNil(t, rejectPacket)
	assert.Len(t, rejectPacket, ipv6.HeaderLen+8+1000)
	assert.Equal(t, largePkt[:1000], rejectPacket[ipv6.HeaderLen+8:])
}

func Test_CreateRejectPacketIPv6_TCP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// TCP SYN packet (next header 6)
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00                             // src port high
	tcpPayload[1] = 0x50                             // src port low (80)
	tcpPayload[2] = 0x01                             // dst port high
	tcpPayload[3] = 0xBB                             // dst port low (443)
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000) // seq
	binary.BigEndian.PutUint32(tcpPayload[8:], 0)    // ack seq
	tcpPayload[12] = (20 >> 2) << 4                  // data offset
	tcpPayload[13] = 0b00000010                      // SYN flag

	packet := makeIPv6Packet(src, dst, 6, tcpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Expected: 40 (ipv6 hdr) + 20 (tcp RST)
	expectedLen := ipv6.HeaderLen + 20
	assert.Len(t, rejectPacket, expectedLen)

	// Verify version
	assert.Equal(t, byte(ipv6.Version<<4), rejectPacket[0]&0xf0)
	// Verify next header is TCP (6)
	assert.Equal(t, byte(6), rejectPacket[6])
	// Verify src/dst are swapped
	assert.Equal(t, dst.To16(), net.IP(rejectPacket[8:24]))
	assert.Equal(t, src.To16(), net.IP(rejectPacket[24:40]))
	// Verify ports are swapped
	tcpOut := rejectPacket[ipv6.HeaderLen:]
	assert.Equal(t, uint16(443), binary.BigEndian.Uint16(tcpOut[0:2]))
	assert.Equal(t, uint16(80), binary.BigEndian.Uint16(tcpOut[2:4]))
	// RST+ACK flags (since input was SYN without ACK)
	assert.Equal(t, byte(0b00010100), tcpOut[13])
	// ack_seq = original seq (1000) + SYN (1) + FIN (0) + segment data (0)
	assert.Equal(t, uint32(1001), binary.BigEndian.Uint32(tcpOut[8:]))
}

func Test_CreateRejectPacketIPv6_TCPWithACK(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// TCP packet with ACK set
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00
	tcpPayload[1] = 0x50
	tcpPayload[2] = 0x01
	tcpPayload[3] = 0xBB
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000) // seq
	binary.BigEndian.PutUint32(tcpPayload[8:], 2000) // ack seq
	tcpPayload[12] = (20 >> 2) << 4                  // data offset
	tcpPayload[13] = 0b00010000                      // ACK flag

	packet := makeIPv6Packet(src, dst, 6, tcpPayload)

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	tcpOut := rejectPacket[ipv6.HeaderLen:]
	// RST only (no ACK) since input had ACK
	assert.Equal(t, byte(0b00000100), tcpOut[13])
	// seq = original ack_seq
	assert.Equal(t, uint32(2000), binary.BigEndian.Uint32(tcpOut[4:]))
}

func Test_CreateRejectPacketIPv6_NoICMPError(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")
	out := make([]byte, MaxRejectPacketSize)

	// ICMPv6 error types (1-4) should not generate reject packets
	for icmpType := byte(1); icmpType <= 4; icmpType++ {
		payload := make([]byte, 8)
		payload[0] = icmpType
		packet := makeIPv6Packet(src, dst, 58, payload)

		rejectPacket := CreateRejectPacket(packet, out)
		assert.Nil(t, rejectPacket, "ICMPv6 type %d should not generate a reject packet", icmpType)
	}

	// ICMPv6 non-error types should still generate reject packets
	nonErrorTypes := []byte{128, 129, 133, 134}
	for _, icmpType := range nonErrorTypes {
		payload := make([]byte, 8)
		payload[0] = icmpType
		packet := makeIPv6Packet(src, dst, 58, payload)

		rejectPacket := CreateRejectPacket(packet, out)
		assert.NotNil(t, rejectPacket, "ICMPv6 type %d should generate a reject packet", icmpType)
	}
}

func Test_CreateRejectPacketIPv6_TooShort(t *testing.T) {
	// Packet too short to be valid IPv6
	out := make([]byte, MaxRejectPacketSize)
	assert.Nil(t, CreateRejectPacket([]byte{0x60}, out))
	assert.Nil(t, CreateRejectPacket(make([]byte, 39), out))
}

func Test_CreateRejectPacketIPv6_ExtensionHeaders(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// IPv6 + Hop-by-Hop extension header + TCP
	hopByHop := []byte{
		6,    // next header: TCP
		0,    // length (8 bytes total)
		0, 0, // padding
		0, 0, 0, 0,
	}
	tcpPayload := make([]byte, 20)
	tcpPayload[0] = 0x00
	tcpPayload[1] = 0x50
	tcpPayload[2] = 0x01
	tcpPayload[3] = 0xBB
	binary.BigEndian.PutUint32(tcpPayload[4:], 1000)
	binary.BigEndian.PutUint32(tcpPayload[8:], 2000)
	tcpPayload[12] = (20 >> 2) << 4
	tcpPayload[13] = 0b00010000 // ACK

	payload := append(hopByHop, tcpPayload...)
	packet := makeIPv6Packet(src, dst, 0, payload) // next header 0 = Hop-by-Hop

	out := make([]byte, MaxRejectPacketSize)
	rejectPacket := CreateRejectPacket(packet, out)
	assert.NotNil(t, rejectPacket)

	// Should produce TCP RST
	expectedLen := ipv6.HeaderLen + 20
	assert.Len(t, rejectPacket, expectedLen)
	assert.Equal(t, byte(6), rejectPacket[6]) // next header is TCP
	tcpOut := rejectPacket[ipv6.HeaderLen:]
	assert.Equal(t, byte(0b00000100), tcpOut[13]) // RST only
}

func TestCreateICMPEchoResponse_IPv4(t *testing.T) {
	// Build a simple IPv4 ICMP Echo Request
	packet := make([]byte, 28)
	packet[0] = 0x45                                   // version 4, IHL 5
	binary.BigEndian.PutUint16(packet[2:], uint16(28)) // total length
	packet[8] = 64                                     // TTL
	packet[9] = 1                                      // protocol ICMP
	copy(packet[12:16], net.IPv4(10, 0, 0, 1).To4())   // src
	copy(packet[16:20], net.IPv4(10, 0, 0, 2).To4())   // dst
	packet[20] = 8                                     // ICMP Echo Request

	out := make([]byte, len(packet))
	result := CreateICMPEchoResponse(packet, out)
	assert.NotNil(t, result)
	assert.Equal(t, byte(0x45), result[0])
	// src/dst swapped
	assert.Equal(t, net.IPv4(10, 0, 0, 2).To4(), net.IP(result[12:16]))
	assert.Equal(t, net.IPv4(10, 0, 0, 1).To4(), net.IP(result[16:20]))
	// ICMP Echo Reply
	assert.Equal(t, byte(0), result[20])
}

func TestCreateICMPEchoResponse_IPv6(t *testing.T) {
	src := net.ParseIP("fd00::1").To16()
	dst := net.ParseIP("fd00::2").To16()

	// Build an IPv6 ICMPv6 Echo Request packet
	// IPv6 header (40 bytes) + ICMPv6 (8 bytes)
	packet := make([]byte, 48)
	packet[0] = 0x60        // version 6
	payloadLen := uint16(8) // ICMPv6 header only
	binary.BigEndian.PutUint16(packet[4:], payloadLen)
	packet[6] = 58           // Next Header: ICMPv6
	packet[7] = 64           // Hop Limit
	copy(packet[8:24], src)  // src address
	copy(packet[24:40], dst) // dst address

	// ICMPv6 Echo Request
	icmp := packet[40:]
	icmp[0] = 128                           // type: Echo Request
	icmp[1] = 0                             // code
	binary.BigEndian.PutUint16(icmp[4:], 1) // identifier
	binary.BigEndian.PutUint16(icmp[6:], 1) // sequence number

	// Compute correct checksum for the request
	csum := ipv6PseudoheaderChecksum(src, dst, 58, uint32(payloadLen))
	binary.BigEndian.PutUint16(icmp[2:], tcpipChecksum(icmp, csum))

	out := make([]byte, len(packet))
	result := CreateICMPEchoResponse(packet, out)
	assert.NotNil(t, result)

	// Version should still be 6
	assert.Equal(t, byte(6), result[0]>>4)
	// src/dst swapped
	assert.Equal(t, dst, net.IP(result[8:24]))
	assert.Equal(t, src, net.IP(result[24:40]))
	// ICMPv6 Echo Reply type
	assert.Equal(t, byte(129), result[40])

	// Verify checksum is valid (tcpipChecksum returns 0 when data+checksum is correct)
	respIcmp := result[40:]
	verifyCsum := ipv6PseudoheaderChecksum(result[8:24], result[24:40], 58, uint32(payloadLen))
	assert.Equal(t, uint16(0), tcpipChecksum(respIcmp, verifyCsum))
}

func TestCreateICMPEchoResponse_IPv6_NotEchoRequest(t *testing.T) {
	src := net.ParseIP("fd00::1").To16()
	dst := net.ParseIP("fd00::2").To16()

	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], 8)
	packet[6] = 58
	packet[7] = 64
	copy(packet[8:24], src)
	copy(packet[24:40], dst)

	// ICMPv6 type 1 (Destination Unreachable) - not Echo Request
	packet[40] = 1

	out := make([]byte, len(packet))
	result := CreateICMPEchoResponse(packet, out)
	assert.Nil(t, result)
}

func TestCreateICMPEchoResponse_IPv6_NotICMPv6(t *testing.T) {
	src := net.ParseIP("fd00::1").To16()
	dst := net.ParseIP("fd00::2").To16()

	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], 8)
	packet[6] = 6 // TCP, not ICMPv6
	packet[7] = 64
	copy(packet[8:24], src)
	copy(packet[24:40], dst)

	out := make([]byte, len(packet))
	result := CreateICMPEchoResponse(packet, out)
	assert.Nil(t, result)
}

func TestIPv6FindUpperProtocol(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	// extHdr builds one 8-byte-unit extension header: next, hdrExtLen
	// ((extra+1)*8 bytes total), padded to size.
	extHdr := func(next uint8, extra int) []byte {
		b := make([]byte, (extra+1)*8)
		b[0] = next
		b[1] = uint8(extra)
		return b
	}

	t.Run("no extension headers", func(t *testing.T) {
		for _, proto := range []uint8{6, 17, 58} {
			nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, proto, make([]byte, 20)))
			assert.Equal(t, proto, nh)
			assert.Equal(t, ipv6.HeaderLen, offset)
			assert.False(t, frag)
		}
	})

	t.Run("hop-by-hop then TCP", func(t *testing.T) {
		payload := append(extHdr(6, 0), make([]byte, 20)...)
		nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 0, payload))
		assert.Equal(t, uint8(6), nh)
		assert.Equal(t, ipv6.HeaderLen+8, offset)
		assert.False(t, frag)
	})

	t.Run("chained headers honor length units", func(t *testing.T) {
		// Hop-by-Hop (8B) -> Dest Options (16B) -> Routing (8B) -> UDP.
		payload := extHdr(60, 0)
		payload = append(payload, extHdr(43, 1)...)
		payload = append(payload, extHdr(17, 0)...)
		payload = append(payload, make([]byte, 8)...)
		nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 0, payload))
		assert.Equal(t, uint8(17), nh)
		assert.Equal(t, ipv6.HeaderLen+8+16+8, offset)
		assert.False(t, frag)
	})

	t.Run("AH length is in 4-byte units plus 2", func(t *testing.T) {
		// AH payload-len byte 4 -> (4+2)*4 = 24 bytes on the wire.
		ah := make([]byte, 24)
		ah[0] = 6
		ah[1] = 4
		payload := append(ah, make([]byte, 20)...)
		nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 51, payload))
		assert.Equal(t, uint8(6), nh)
		assert.Equal(t, ipv6.HeaderLen+24, offset)
		assert.False(t, frag)
	})

	t.Run("first fragment walks to the transport header", func(t *testing.T) {
		frag := make([]byte, 8)
		frag[0] = 17
		binary.BigEndian.PutUint16(frag[2:4], 0x0001) // offset 0, M=1
		payload := append(frag, make([]byte, 8)...)
		nh, offset, isFrag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 44, payload))
		assert.Equal(t, uint8(17), nh)
		assert.Equal(t, ipv6.HeaderLen+8, offset)
		assert.False(t, isFrag, "first fragment carries the real transport header")
	})

	t.Run("non-first fragment is flagged", func(t *testing.T) {
		frag := make([]byte, 8)
		frag[0] = 17
		binary.BigEndian.PutUint16(frag[2:4], 1<<3) // offset 1, M=0
		payload := append(frag, make([]byte, 8)...)
		nh, _, isFrag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 44, payload))
		assert.Equal(t, uint8(17), nh, "fragment header still names the flow's L4")
		assert.True(t, isFrag, "offset points at fragment payload, not a header")
	})

	t.Run("ESP terminates the walk", func(t *testing.T) {
		nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 50, make([]byte, 16)))
		assert.Equal(t, uint8(50), nh)
		assert.Equal(t, ipv6.HeaderLen, offset)
		assert.False(t, frag)
	})

	t.Run("unknown protocol terminates the walk", func(t *testing.T) {
		nh, offset, _ := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 132, make([]byte, 16))) // SCTP
		assert.Equal(t, uint8(132), nh)
		assert.Equal(t, ipv6.HeaderLen, offset)
	})

	t.Run("truncated extension header stops the walk", func(t *testing.T) {
		// Next header says Hop-by-Hop but the packet ends at the IPv6 header.
		nh, offset, frag := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 0, nil))
		assert.Equal(t, uint8(0), nh, "unresolvable chain returns the extension header it stopped on")
		assert.Equal(t, ipv6.HeaderLen, offset)
		assert.False(t, frag)
	})

	t.Run("crafted over-long chain hits the cap", func(t *testing.T) {
		// Ten chained Hop-by-Hop headers, then TCP. Illegal per RFC 8200
		// (Hop-by-Hop may only appear first); the cap must stop the walk
		// before it resolves rather than crawling arbitrary crafted chains.
		var payload []byte
		for i := 0; i < 9; i++ {
			payload = append(payload, extHdr(0, 0)...)
		}
		payload = append(payload, extHdr(6, 0)...)
		payload = append(payload, make([]byte, 20)...)
		nh, _, _ := IPv6FindUpperProtocol(makeIPv6Packet(src, dst, 0, payload))
		assert.Equal(t, uint8(0), nh, "walk must stop at the cap, not resolve to TCP")
	})

	t.Run("packet shorter than an IPv6 header", func(t *testing.T) {
		nh, offset, frag := IPv6FindUpperProtocol(make([]byte, 39))
		assert.Equal(t, uint8(59), nh) // IPPROTO_NONE
		assert.Equal(t, 0, offset)
		assert.False(t, frag)
	})
}
