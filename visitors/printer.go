package visitors

import (
	"fmt"
	"net"
	"os"
	"strings"

	// "github.com/alecthomas/repr"
	"github.com/bwNetFlow/flowfilter/parser"
)

type Printer struct {
	output []string
}

func (p *Printer) Print(expr *parser.Expression) {
	err := parser.Visit(expr, p.Visit) // run the Visitor
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(strings.Join(p.output, " "))
}

func (p *Printer) String(expr *parser.Expression) string {
	err := parser.Visit(expr, p.Visit) // run the Visitor
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return strings.Join(p.output, " ")
}

func (p *Printer) Visit(n parser.Node, next func() error) error {
	// Before processing a node's children, do different things for
	// different types of nodes.
	// This 'before' part must cover all node types which are returned by
	// any other node's `children` method, as it's got a default clause to
	// annoy devs when the AST changes.
	// repr.Println(n)
	switch node := n.(type) {
	case *parser.AddressMatch:
		p.output = append(p.output, "address")
		// print both fields
		if node.Mask != nil {
			var mask net.IPMask
			if node.Address.To4() != nil {
				mask = net.CIDRMask(int(*node.Mask), 32)
			} else {
				mask = net.CIDRMask(int(*node.Mask), 128)
			}
			ipnet := &net.IPNet{*node.Address, mask}
			p.output = append(p.output, fmt.Sprint(ipnet))
		} else {
			p.output = append(p.output, fmt.Sprint(*node.Address))
		}
	case *parser.Address:
	case *parser.AsnRangeMatch:
		p.output = append(p.output, "asn")
	case *parser.Boolean:
		if *node {
			p.output = append(p.output, "not")
		}
	case *parser.BpsRangeMatch:
		p.output = append(p.output, "bps")
	case *parser.ByteRangeMatch:
		p.output = append(p.output, "bytes")
	case *parser.CidRangeMatch:
		p.output = append(p.output, "cid")
	case *parser.DirectionalMatchGroup: // no syntax elements here
	case *parser.DurationRangeMatch:
		p.output = append(p.output, "duration")
	case *parser.DscpKey:
		var magic string
		switch *node {
		case 0b000000:
			magic = "default"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.DscpMatch:
		p.output = append(p.output, "dscp")
	case *parser.EcnKey:
		var magic string
		switch *node {
		case 0b11:
			magic = "ce"
		case 0b01:
			magic = "ect1"
		case 0b10:
			magic = "ect0"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.EcnMatch:
		p.output = append(p.output, "ecn")
	case *parser.EtypeKey:
		var magic string
		switch *node {
		case 0x0800:
			magic = "ipv4"
		case 0x0806:
			magic = "arp"
		case 0x86DD:
			magic = "ipv6"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.EtypeMatch:
		p.output = append(p.output, "etype")
	case *parser.Expression: // no syntax elements here
	case *parser.FlowDirectionMatch:
		p.output = append(p.output, "direction")
	case *parser.IcmpMatch:
		p.output = append(p.output, "icmp")
	case *parser.IfSpeedRangeMatch:
		p.output = append(p.output, "speed")
	case *parser.InterfaceMatch:
		p.output = append(p.output, "interface")
	case *parser.IPTosRangeMatch:
		p.output = append(p.output, "iptos")
	case *parser.NetsizeRangeMatch:
		p.output = append(p.output, "netsize")
	case *parser.NextHopMatch:
		p.output = append(p.output, "nexthop")
	case *parser.NormalizedMatch:
		p.output = append(p.output, "normalized")
	case *parser.Number:
		p.output = append(p.output, fmt.Sprintf("%d", *node))
	case *parser.PacketRangeMatch:
		p.output = append(p.output, "packets")
	case *parser.PortRangeMatch:
		p.output = append(p.output, "port")
	case *parser.PpsRangeMatch:
		p.output = append(p.output, "pps")
	case *parser.ProtoKey:
		var magic string
		switch *node {
		case 1:
			magic = "icmp"
		case 6:
			magic = "tcp"
		case 17:
			magic = "udp"
		case 58:
			magic = "icmpv6"
		case 94:
			magic = "ipip"
		case 112:
			magic = "vrrp"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.ProtoMatch:
		p.output = append(p.output, "proto")
	case *parser.RangeEnd:
		p.output = append(p.output, fmt.Sprintf("- %d", *node))
	case *parser.RegularMatchGroup: // no syntax elements here
	case *parser.RemoteCountryMatch:
		p.output = append(p.output, "country")
	case *parser.RouterMatch:
		p.output = append(p.output, "router")
	case *parser.SamplingRateRangeMatch:
		p.output = append(p.output, "samplingrate")
	case *parser.Statement:
		// in case it's a SubExpression, wrap it
		if node.SubExpression != nil {
			p.output = append(p.output, "(")
		} // else children will handle themselves
	case *parser.StatusKey:
		var magic string
		switch *node {
		case 0b01000000:
			magic = "forwarded"
		case 0b10000000:
			magic = "dropped"
		case 0b10000001:
			magic = "acldeny"
		case 0b10000010:
			magic = "acldrop"
		case 0b10000011:
			magic = "unroutable"
		case 0b11000000:
			magic = "consumed"
		case 0b10001010:
			magic = "policerdrop"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.StatusMatch:
		p.output = append(p.output, "status")
	case *parser.String:
		p.output = append(p.output, string(*node))
	case *parser.TcpFlagKey:
		var magic string
		switch *node {
		case 0b000000001:
			magic = "fin"
		case 0b000010001:
			magic = "finack"
		case 0b000000010:
			magic = "syn"
		case 0b000000100:
			magic = "rst"
		case 0b000001000:
			magic = "psh"
		case 0b000010000:
			magic = "ack"
		case 0b000100000:
			magic = "urg"
		case 0b000010010:
			magic = "synack"
		case 0b010000000:
			magic = "cwr"
		case 0b100000000:
			magic = "ece"
		}
		if magic != "" {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.TcpFlagMatch:
		p.output = append(p.output, "tcpflags")
	case *parser.VrfRangeMatch:
		p.output = append(p.output, "vrf")
	default:
		return fmt.Errorf("Encountered unknown node type: %T", node)
	}

	err := next() // descend to child nodes
	if err != nil {
		return err
	}

	// After processing all children...
	switch node := n.(type) {
	case *parser.Statement:
		if node.SubExpression != nil {
			p.output = append(p.output, ")")
		}
	default:
		_ = node
	}
	return nil
}
