package visitors

import (
	"fmt"
	"net"
	"os"
	"strings"

	// "github.com/alecthomas/repr"
	"github.com/BelWue/flowfilter/parser"
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

func reverseMap(m map[string]uint64) map[uint64]string {
	n := make(map[uint64]string)
	for k, v := range m {
		n[v] = k
	}
	return n
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
		if magic, ok := reverseMap(parser.DscpMagicMap)[uint64(*node)]; ok {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.DscpMatch:
		p.output = append(p.output, "dscp")
	case *parser.EcnKey:
		if magic, ok := reverseMap(parser.EcnMagicMap)[uint64(*node)]; ok {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.EcnMatch:
		p.output = append(p.output, "ecn")
	case *parser.EtypeKey:
		if magic, ok := reverseMap(parser.EtypeMagicMap)[uint64(*node)]; ok {
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
	case *parser.LocalPrefRangeMatch:
		p.output = append(p.output, "localpref")
	case *parser.MedRangeMatch:
		p.output = append(p.output, "med")
	case *parser.NetsizeRangeMatch:
		p.output = append(p.output, "netsize")
	case *parser.NextHopMatch:
		p.output = append(p.output, "nexthop")
	case *parser.NextHopAsnMatch:
		p.output = append(p.output, "nexthopasn")
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
	case *parser.PassesThroughListMatch:
		p.output = append(p.output, "passes-through")
	case *parser.ProtoKey:
		if magic, ok := reverseMap(parser.ProtoMagicMap)[uint64(*node)]; ok {
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
		if magic, ok := reverseMap(parser.StatusMagicMap)[uint64(*node)]; ok {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.StatusMatch:
		p.output = append(p.output, "status")
	case *parser.String:
		p.output = append(p.output, string(*node))
	case *parser.TcpFlagsKey:
		if magic, ok := reverseMap(parser.TcpFlagsMagicMap)[uint64(*node)]; ok {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, fmt.Sprintf("%d", *node))
		}
	case *parser.TcpFlagsMatch:
		p.output = append(p.output, "tcpflags")
	case *parser.RpkiKey:
		if magic, ok := reverseMap(parser.RpkiMagicMap)[uint64(*node)]; ok {
			p.output = append(p.output, magic)
		} else {
			p.output = append(p.output, "?")
		}
	case *parser.RpkiMatch:
		p.output = append(p.output, "rpki")
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
