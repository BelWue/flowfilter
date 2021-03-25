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
		IPTos:            4,          // uint32
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
		`address 10.0.0.200`,
		`address 10.0.0.0/24`,
		`src address 10.0.0.200`,
		`dst address 2001:7c0:0:254::6`,
		`address 2001:7c0:0:254::/64`,
		`address 10.0.0.200 or address 8.8.8.8`,
		`proto 1`,
		`proto icmp`,
		`not proto 7`,
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
		`etype 0x0800`,
		`etype 2048`,
		`etype ipv4`,
		`iface 1`,
		`src interface 1`,
		`iface name 'Hu'`,
		`iface name "Te"`,
		`iface desc 'cust'`,
		`iface speed >0`,
		`src iface speed 10-1000000`,
		`bytes 20490000`,
		`packets 0-400`,
		`packets <1000`,
		`bytes >1000`,
		`samplingrate 32`,
		`asn 553`,
		`asn <65000`,
		`src asn 553`,
		`cid 123 and incoming`,
		`not cid 1283`,
		`router 10.0.0.1`,
		`country dE`,
		`direction incoming`,
		`incoming and country de`,
		`duration >100 and not status dropped`,
		`status forwarded`,
		`not tcpflags ack`,
		`nexthop 10.11.0.1`,
		`netsize <24`,
		`vrf 1`,
		`dst vrf >1`,
		`not normalized`,
		`icmp type 4`,
		`bps 655680`,
		`duration 250`,
		`bps >100`,
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
		`address 10.0.0.201`,
		// `address 10.0.0.0/25`,
		`src address 10.1.0.200`,
		`dst address 10.0.0.200`,
		`address 10.0.0.200 and address 8.8.8.8`,
		`proto 7`,
		`port 2 and port 0`,
		`port 2-100`,
		`port <0`,
		`etype 0x0801`,
		`iface speed <0`,
		`iface desc "nooooope"`,
		`bytes <42`,
		`packets > 4242`,
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
