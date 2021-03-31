package visitors

import (
	// "fmt"
	// "net"
	"testing"

	"github.com/bwNetFlow/flowfilter/parser"
	flow "github.com/bwNetFlow/protobuf/go"
)

var (
	// TODO: The following FlowMessage declaration doubles as a progress tracker
	flowmsg = &flow.FlowMessage{
		// directional fields
		SrcAddr:      []byte{10, 0, 0, 200},
		DstAddr:      []byte{32, 1, 7, 192, 0, 0, 2, 84, 0, 0, 0, 0, 0, 0, 0, 6},
		SrcPort:      0,           // uint32
		DstPort:      1024,        // uint32
		SrcAS:        553,         // uint32
		DstAS:        12345,       // uint32
		InIf:         1,           // uint32
		OutIf:        2,           // uint32
		SrcIfName:    "Hu0/1/1/4", // string // TODO: check how to use plain goflow
		SrcIfDesc:    "some IX",   // string // TODO: check how to use plain goflow
		SrcIfSpeed:   100000,      // uint32 // TODO: check how to use plain goflow
		DstIfName:    "Te1/1/1/1", // string // TODO: check how to use plain goflow
		DstIfDesc:    "customer",  // string // TODO: check how to use plain goflow
		DstIfSpeed:   10000,       // uint32 // TODO: check how to use plain goflow
		SrcNet:       24,          // uint32
		DstNet:       11,          // uint32
		IngressVrfID: 1,           // uint32
		EgressVrfID:  2,           // uint32

		// complex fields
		SamplerAddress:   []byte{10, 0, 0, 1},
		NextHop:          []byte{10, 11, 0, 1},
		Bytes:            20490000,   // uint64
		Packets:          400,        // uint64
		FlowDirection:    0,          // uint32
		Normalized:       0,          //  int32 // TODO: check how to use plain goflow
		TimeFlowStart:    10000,      // uint64
		TimeFlowEnd:      10250,      // uint64
		RemoteCountry:    "DE",       // string // TODO: check how to use plain goflow
		Etype:            0x0800,     // uint32
		Proto:            1,          // uint32
		ForwardingStatus: 0b01000010, // uint32
		TCPFlags:         0b010010,   // uint32
		IPTos:            0b00000011, // uint32
		SamplingRate:     32,         // uint64
		Cid:              123,        // uint32

		// TODO: set but kinda useless for a filter language?
		// Type:		// int32 // 0, sFlow 1, NFv5 2, NFv9 3, IPFIX 4
		// TimeReceived:	// uint64
		// SequenceNum:		// uint32

		// stuff thats unset
		// IPTTL:               // uint32
		// SrcMac:		// uint64
		// DstMac:		// uint64
		// SrcVlan:		// uint32
		// DstVlan:		// uint32
		// VlanId:		// uint32
		// IcmpType:		// uint32
		// IcmpCode:		// uint32
		// IPv6FlowLabel:	// uint32
		// FragmentId:		// uint32
		// FragmentOffset:	// uint32
		// BiFlowDirection:	// uint32
		// NextHopAS:		// uint32
		// HasEncap:		// bool
		// SrcAddrEncap:	// []byte
		// DstAddrEncap:	// []byte
		// ProtoEncap:		// uint32
		// EtypeEncap:		// uint32
		// IPTosEncap:		// uint32
		// IPTTLEncap:		// uint32
		// IPv6FlowLabelEncap:	// uint32
		// FragmentIdEncap:	// uint32
		// FragmentOffsetEncap:	// uint32
		// HasMPLS:		// bool
		// MPLSCount:		// uint32
		// MPLS1TTL:		// uint32
		// MPLS1Label:		// uint32
		// MPLS2TTL:		// uint32
		// MPLS2Label:		// uint32
		// MPLS3TTL:		// uint32
		// MPLS3Label:		// uint32
		// MPLSLastTTL:		// uint32
		// MPLSLastLabel:	// uint32
		// HasPPP:		// bool
		// PPPAddressControl:	// uint32
		// CidString:		// string
		// ProtoName:		// string
	}
)

func TestAccept(t *testing.T) {
	tests := []string{
		``,
		// `address` `<address>[/<int>]`
		`address 10.0.0.200`,
		`address 10.0.0.0/24`,
		`src address 10.0.0.200`,
		`dst address 2001:7c0:0:254::6`,
		`address 2001:7c0:0:254::/64`,
		`address 10.0.0.200 or address 8.8.8.8`,
		// `i[nter]face` `<int>`
		`iface 1`,
		`src interface 1`,
		`iface name 'Hu'`,
		`iface name "Te"`,
		`iface desc 'cust'`,
		`iface speed >0`,
		`src iface speed 10-1000000`,
		// `port` `<range>`
		`port 0`,
		`port 0-100`,
		`port 1024-1024`,
		`port 0-10000`,
		`src port 0-10000`,
		`dst port 0-10000`,
		`src port 0`,
		`dst port 1024`,
		`port >1`,
		`port <1`,
		// `asn` `<range>`
		`asn 553`,
		`asn <65000`,
		`src asn 553`,
		// `netsize` `<range>`
		`netsize <24`,
		// `vrf` `<range>`
		`vrf 1`,
		`dst vrf >1`,
		// `router` `<address>`
		`router 10.0.0.1`,
		// `nexthop` `<address>`
		`nexthop 10.11.0.1`,
		// `bytes` `<range>`
		`bytes 20490000`,
		`bytes >1000`,
		// `packets` `<range>`
		`packets 0-400`,
		`packets <1000`,
		// `country` `<cc>`
		`country dE`,
		// `direction` `incoming|outgoing`
		`direction incoming`,
		`incoming and country de`,
		// `normalized`
		`not normalized`,
		// `duration` `<range>`
		`duration >100 and not status dropped`,
		`duration 250`,
		// `dscp` `<int>|dscp
		`dscp default`,
		// `ecn` `<int>|ecn
		`ecn ce`,
		// `etype` `<int>|etype
		`etype 0x0800`,
		`etype 2048`,
		`etype ipv4`,
		// `proto` `<int>|proto
		`proto 1`,
		`proto icmp`,
		`not proto 7`,
		// `status` `<int>|status
		`status forwarded`,
		// `tcpflags` `<int>|tcpflag
		`not tcpflags ack`,
		// `iptos` <range>
		`iptos 0b0-0b11`,
		// `samplingrate` `<range>`
		`samplingrate 32`,
		`samplingrate <512`,
		// `cid` `<range>`
		`cid 123`,
		`not cid 1283`,
		// `icmp type` `<int>`
		`icmp type 4`,
		// `icmp code` `<int>`
		`icmp code 0`,
		// `bps` `<range>`
		`bps 655680`,
		`bps >100`,
		// `pps` `<range>`
		`pps >0`,
	}

	for _, test := range tests {
		expr, err := parser.Parse(test)
		if err != nil {
			t.Errorf("Filter `%s` failed to parse with error:\n%s\n", test, err)
		}
		filter := &Filter{}
		result, err := filter.CheckFlow(expr, flowmsg)
		if err != nil {
			t.Error(err)
		}
		if !result {
			t.Errorf("Filter `%s` does not match the test flow.\n", test)
		}
	}
}

func TestReject(t *testing.T) {
	tests := []string{
		// `address` `<address>[/<int>]`
		`address 10.0.0.201`,
		`address 10.0.0.0/30`,
		`src address 10.0.0.201`,
		`dst address 2001:7c0:0:254::8`,
		`address 2001:7c0:0:255::/64`,
		`address 10.0.0.201 or address 8.8.8.8`,
		// `i[nter]face` `<int>`
		`iface 8`,
		`src interface 2`,
		`iface name 'gi'`,
		`iface desc 'king'`,
		`iface speed <0`,
		`src iface speed 10-10`,
		// `port` `<range>`
		`port 1`,
		`port 1-100`,
		`port 1-1023`,
		`src port 1-10000`,
		`dst port 0-1023`,
		`src port 1`,
		`dst port 1023`,
		`port <0`,
		// `asn` `<range>`
		`asn 554`,
		`asn >65000`,
		`src asn 551`,
		// `netsize` `<range>`
		`netsize >24`,
		// `vrf` `<range>`
		`vrf 0`,
		`dst vrf <1`,
		// `router` `<address>`
		`router 10.0.0.2`,
		// `nexthop` `<address>`
		`nexthop 10.11.0.2`,
		// `bytes` `<range>`
		`bytes 2049`,
		`bytes <1000`,
		// `packets` `<range>`
		`packets 1110-1400`,
		`packets >1000`,
		// `country` `<cc>`
		`country Es`,
		// `direction` `incoming|outgoing`
		`direction outgoing`,
		`outgoing and country de`,
		// `normalized`
		`normalized`,
		// `duration` `<range>`
		`duration <100 and not status dropped`,
		`duration 251`,
		// `etype` `<int>|etype
		`etype 0x0801`,
		`etype 2042`,
		`etype ipv6`,
		// `proto` `<int>|proto
		`proto 2`,
		`proto tcp`,
		`not proto 1`,
		// `status` `<int>|status
		`status acldeny`,
		// `tcpflags` `<int>|tcpflag
		`tcpflags ack`,
		// `dsfield|iptos` <int>|dsstring
		// `samplingrate` `<range>`
		`samplingrate 31`,
		`samplingrate >512`,
		// `cid` `<range>`
		`cid 1234`,
		`not cid 123`,
		// `icmp type` `<int>`
		`icmp type 2`,
		// `icmp code` `<int>`
		`icmp code 1`,
		// `bps` `<range>`
		`bps 655681`,
		`bps <100`,
		// `pps` `<range>`
		`pps <0`,
	}

	for _, test := range tests {
		expr, err := parser.Parse(test)
		if err != nil {
			t.Errorf("Filter `%s` failed to parse with error:\n%s\n", test, err)
		}
		filter := &Filter{}
		result, err := filter.CheckFlow(expr, flowmsg)
		if err != nil {
			t.Error(err)
		}
		if result {
			t.Errorf("Filter `%s` does match the test flow.\n", test)
		}
	}
}

func TestError(t *testing.T) {
	// This test is for errors that are caught and thrown by the flow
	// filter visitor alone. Hence, we still error out if an error occurs
	// at parsing, although that's always a problem of these tests.
	tests := []string{
		`port 1024-10`,
		`iface speed 1024-10`,
	}

	for _, test := range tests {
		expr, err := parser.Parse(test)
		if err != nil {
			t.Errorf("Filter `%s` failed to parse with error:\n%s\n", test, err)
		}
		filter := &Filter{}
		_, err = filter.CheckFlow(expr, flowmsg)
		if err == nil {
			t.Errorf("Filter `%s` produced no error.\n", test)
		}
	}
}
