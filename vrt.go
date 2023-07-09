package vrt

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
	This layer provides decoding and encoding for VITA Radio Transport (VRT).
	https://vitastore.dpdcart.com/product/168632?__dpd_cart=2bdffd15-8c70-4406-acdd-5f076ac5d51e
	From VITA 49.0-2015 (R2021) Standard Figure 6.1-1

	  3                   2                   1                   0
	1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |PktType|C|T|R R|TSI|TSF|PktCnt |          Packet Size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Stream Identifier (1 Word, Optional)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Class Identifier (2 Words, Optional)             |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Integer-seconds Timestamp (1 Word, Optional)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Fractional-seconds Timestamp (2 Words, Optional)        |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Data Payload (Variable, Mandatory)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Trailer (1 Word, Optional)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// LayerTypeVRT handles the VRT packet processing for gopacket
var LayerTypeVRT = gopacket.RegisterLayerType(4900, gopacket.LayerTypeMetadata{Name: "VRT", Decoder: gopacket.DecodeFunc(decodeVRT)})

// constant representing the minimum size of a VRT packet
const vrtMinimumRecordSizeInBytes int = 8

// VitaPacketType specifies the VRT Packet Type
type VitaPacketType uint8

// constants representing different VRT packet types
const (
	IFData            VitaPacketType = iota // 0
	IFDataWithStream                        // 1
	ExtData                                 // 2
	ExtDataWithStream                       // 3
	IFContext                               // 4
	ExtContext                              // 5
)

// type PadBitCount uint8

// ClassID makes it possible for a VRT Packet Stream receiver to determine the identity of
// both the Information Class used for the application and the Packet Class from which each
// received packet was made.
type ClassID struct {
	OUI uint32 // 0xFC
	// PadBitCount	// 0x03
	PacketClassCode      uint16
	InformationClassCode uint16
}

// type ClassPresent uint8
// type TrailerPresent uint8

// TSI is the Timestamp Integer type
type TSI uint8

// constants representing different Timestamp Integer types
const (
	TSINone  TSI = iota // 0
	TSIUTC              // 1
	TSIGPS              // 2
	TSIOther            // 3
)

// TSF is the Timestamp Fractional type
type TSF uint8

// constants representing different Timestamp Fractional types
const (
	TSFNone        TSF = iota // 0
	TSFSampleCount            // 1
	TSFRealTime               // 2
	TSFFreeRunning            // 3
)

// PacketCount contains a modulo-16 count of IF Data packets for an IF Data Packet Stream
type PacketCount uint8

// Header is the representation of a VRT packet's header.
type Header struct {
	Type        VitaPacketType // F0
	C           bool           // 08
	T           bool           // 04
	TSI         TSI            // C0
	TSF         TSF            // 30
	PacketCount PacketCount    // 0F
	PacketSize  uint16
}

// TODO: IFContextHeader/ExtContext

// Trailer is the representation of a VRT packet's trailer.
// This is optional and only appears when the Header.T is set to `true`.
// Will be fully implemented in a future version of this module.
type Trailer struct {
	CalibratedTimeEnable    bool
	ValidDataEnable         bool
	ReferenceLockEnable     bool
	AGCMGCEnable            bool
	DetectedSignalEnable    bool
	SpectralInversionEnable bool
	OverrangeEnable         bool
	SampleLossEnable        bool

	CalibratedTimeIndicator    bool
	ValidDataIndicator         bool
	ReferenceLockIndicator     bool
	AGCMGCIndicator            bool
	DetectedSignalIndicator    bool
	SpectralInversionIndicator bool
	OverrangeIndicator         bool
	SampleLossIndicator        bool

	AssociatedContextPacketCountEnable bool
	AssociatedContextPacketCount       byte // valid 0 - 127
}

// VRT (VITA Radio Transport) is a standard that defines a transport layer protocol
// designed to promote interoperability between RF (radio frequency) receivers and
// signal processing equipment across a wide range of applications.
type VRT struct {
	layers.BaseLayer
	Header        Header
	StreamID      uint32
	ClassID       ClassID
	TimestampInt  uint32
	TimestampFrac uint64
	Payload       []byte
	// Trailer uint32
}

// LayerType returns gopacket.LayerTypeVRT
func (v VRT) LayerType() gopacket.LayerType {
	return LayerTypeVRT
}

// LayerContents returns the VRT layer's contents as a byte array
func (v VRT) LayerContents() (data []byte) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}

	// Temporary fix for G104 (CWE-703 - Unhandled Errors)
	// gopacket's LayerContents interface does not allow an error response
	// so return empty []byte if the serialization has an error
	err := v.SerializeTo(buf, opts)
	if err != nil {
		return []byte(nil)
	}

	return []byte(buf.Bytes())
}

// LayerPayload returns the VRT object's Payload
// VRT packets carry a data payload so the Payload byte slice is retured.
func (v VRT) LayerPayload() []byte {
	return v.Payload
}

// CanDecode returns a set of layers that VRT objects can decode.
// As VRT objects can only decide the VRT layer, we can return just that layer.
// Apparently a single layer type implements LayerClass.
func (v VRT) CanDecode() gopacket.LayerClass {
	return LayerTypeVRT
}

// NextLayerType specifies the next layer that GoPacket should attempt to
// analyse after this (VRT) layer. As VRT packets contain payload
// bytes, there is an additional layer to analyse.
func (v VRT) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// ValidateVrtPacketSize calculates the minimum size of the VRT packet based on the VRT header
// and compares to the size of the VRT packet. VRT packets below the minimum size through an error.
// header.PacketSize is the number of 32 bit words per packet and should always equal size/4.
// FIXME: fix calculations for packet_words vs packet bytes
func ValidateVrtPacketSize(header Header, size uint32) (outputHeaderSize uint16, ouputMinimumWords uint32, err error) {
	var minimumWords uint32 = 1

	switch header.Type {
	case IFDataWithStream:
		minimumWords++ //header + stream_id
	case ExtDataWithStream:
		minimumWords++ //header + stream_id
	case IFContext:
		minimumWords++ //header + stream_id
	case ExtContext:
		minimumWords++ //header + stream_id
	}

	// Check if Class ID is present
	if header.C {
		minimumWords += 2
	}

	// Check if Trailer is present
	if header.T {
		minimumWords++
	}

	// Check if TimestampIntegerSeconds is present
	if header.TSI != TSINone {
		minimumWords++
	}

	// Check if TimestampFractionalSeconds is present
	if header.TSF != TSFNone {
		minimumWords += 2
	}

	// Assume 1 uint32 for payload minimum
	minimumWords++

	// Verify if size is not equal to the calculated minimum size
	if uint32(header.PacketSize) >= minimumWords {
		// Packet is correct size
		return header.PacketSize, minimumWords, nil
	}

	// Something is wrong with the size
	err = fmt.Errorf("malformed VRT packet")
	return header.PacketSize, minimumWords, err
}

// DecodeFromBytes analyses a byte slice and attempts to decode it as a VRT
// record of a UDP packet.
//
// Upon succeeds, it loads the VRT object with information about the packet
// and returns nil.
// Upon failure, it returns an error (non nil).
func (v *VRT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < vrtMinimumRecordSizeInBytes {
		return fmt.Errorf("packet too small for VITA Radio Transport")
	}

	v.BaseLayer = layers.BaseLayer{Contents: data[:]}

	// Offset counter
	var offset uint32 = 0

	// Packet Header
	// fmt.Printf("DEBUG Header byte[0]: [%x]", data[offset])
	v.Header.Type = VitaPacketType((data[offset] & 0xF0) >> 4)
	v.Header.C = data[offset]&0x08 != 0
	v.Header.T = data[offset]&0x04 != 0
	//v.Header.R1 = Reserved1((data[offset] & 0x02))
	//v.Header.R2 = Reserved2((data[offset] & 0x01))
	v.Header.TSI = TSI((data[offset+1] & 0xC0) >> 6)
	v.Header.TSF = TSF((data[offset+1] & 0x30) >> 4)
	v.Header.PacketCount = PacketCount((data[offset+1] & 0x0F))
	v.Header.PacketSize = binary.BigEndian.Uint16(data[offset+2 : offset+4])

	// Update offset for further packet parsing
	offset += 4

	// Verify VRT packet size matches VRT Header's PacketSize
	_, _, err := ValidateVrtPacketSize(v.Header, uint32(len(data)))
	if err != nil {
		return err
	}

	// Set StreamID increment offset when PacketType = IFDataWithStream or ExtDataWithStream
	if (v.Header.Type == IFDataWithStream) || (v.Header.Type == ExtDataWithStream) {
		//has stream id
		v.StreamID = binary.BigEndian.Uint32(data[offset : offset+4]) // [4:8]
		offset += 4
	}

	// ClassID Header is set
	if v.Header.C {
		v.ClassID.OUI = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		v.ClassID.PacketClassCode = binary.BigEndian.Uint16(data[offset : offset+2])
		v.ClassID.InformationClassCode = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}

	// TODO: Is an else statement to set a blank ClassID needed here?

	//// fmt.Printf("DEBUG Header byte[8:16]: [%x]", data[offset+8:offset+16])
	//v.ClassID.OUI = binary.BigEndian.Uint32(data[offset+8 : offset+12])
	////v.ClassID.PadBitCount = PadBitCount((data[offset+11] & 0x1F) >> 3)
	//v.ClassID.PacketClassCode = binary.BigEndian.Uint16(data[offset+12 : offset+14])
	//v.ClassID.InformationClassCode = binary.BigEndian.Uint16(data[offset+14 : offset+16])

	if v.Header.TSI != TSINone {
		v.TimestampInt = binary.BigEndian.Uint32(data[offset : offset+4]) // 16-20
		offset += 4
	} else {
		v.TimestampInt = 0
	}
	//v.TimestampInt = binary.BigEndian.Uint32(data[offset+16 : offset+20]) // 16-20

	if v.Header.TSF != TSFNone {
		v.TimestampFrac = binary.BigEndian.Uint64(data[offset : offset+8]) // 20-28
		offset += 8
	} else {
		v.TimestampFrac = 0
	}
	//v.TimestampFrac = binary.BigEndian.Uint64(data[offset+20 : offset+28]) // 20-28

	// payload := data[28:]
	// res := math.Mod(float64(len(payload)), 4)
	// if res != 0 {
	// 	// TODO append __ 0x00 to payload
	// 	extraBytePadding := make([]byte, int(res))
	// 	payload = append(payload[:], extraBytePadding[:])
	// }
	// TODO: update payload with padded payload

	v.Payload = data[offset:] // 28+
	//v.Payload = data[28:] // 28+

	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (v *VRT) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	data, err := b.PrependBytes(vrtMinimumRecordSizeInBytes)
	if err != nil {
		return err
	}

	// Pack the first few fields into the first 32 bits.
	h := uint8(0)
	h |= (uint8(v.Header.Type) << 4) & 0xF0
	if v.Header.C {
		h |= (uint8(1) << 3) & 0x08
	}
	// h |= (uint8(v.Header.C) << 3) & 0x08
	if v.Header.T {
		h |= (uint8(1) << 2) & 0x04
	}
	//h |= (uint8(v.Header.T) << 2) & 0x04
	//h |= (uint8(v.Header.R1) & 0x02)
	//h |= (uint8(v.Header.R2) & 0x01)

	h1 := uint8(0)
	h1 |= (uint8(v.Header.TSI) << 6) & 0xC0
	h1 |= (uint8(v.Header.TSF) << 4) & 0x30
	h1 |= (uint8(v.Header.PacketCount)) & 0x0F

	data[0] = byte(h)
	data[1] = byte(h1)

	// The remaining fields can just be copied in big endian order.
	binary.BigEndian.PutUint16(data[2:4], uint16(v.Header.PacketSize))
	binary.BigEndian.PutUint32(data[4:8], uint32(v.StreamID))
	// TODO
	//binary.BigEndian.PutUint32(data[4:8], uint32(v.ClassID.OUI))
	//binary.BigEndian.PutUint32(data[4:8], uint32(v.ClassID.PacketClassCode))
	//binary.BigEndian.PutUint32(data[4:8], uint32(v.ClassID.InformationClassCode))
	//binary.BigEndian.PutUint32(data[4:8], uint32(v.TimestampInt))
	//binary.BigEndian.PutUint32(data[4:8], uint32(v.TimestampFrac))

	// Append the VRT Payload based on Payload size
	ex, err := b.AppendBytes(len(v.Payload))
	if err != nil {
		return err
	}
	copy(ex, v.Payload)

	// Add byte padding if Payload does not fall on a byte boundary
	res := math.Mod(float64(len(v.Payload)), 4)
	if res != 0 {
		extraBytePadding := make([]byte, int(res))
		ex, err := b.AppendBytes(int(res))
		if err != nil {
			return err
		}
		copy(ex, extraBytePadding)
	}

	return nil
}

// decodeVRT analyses a byte slice and attempts to decode it as an VRT
// record of a UDP packet.
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
//
// This function should be used in gopacket to register the VRT layer.
func decodeVRT(data []byte, p gopacket.PacketBuilder) error {
	vrt := &VRT{}

	err := vrt.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(vrt)
	return p.NextDecoder(gopacket.LayerTypePayload)
}
