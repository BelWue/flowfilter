package visitors

import (
	"fmt"

	"github.com/BelWue/flowfilter/parser"
)

type Noop struct {
	output []string
}

func (noop *Noop) Visit(n parser.Node, next func() error) error {
	// Before processing a node's children.
	switch node := n.(type) {
	case *parser.Address:
	case *parser.AddressMatch:
	case *parser.AsnRangeMatch:
	case *parser.Boolean:
	case *parser.BpsRangeMatch:
	case *parser.ByteRangeMatch:
	case *parser.CidRangeMatch:
	case *parser.DirectionalMatchGroup:
	case *parser.DscpKey:
	case *parser.DscpMatch:
	case *parser.DurationRangeMatch:
	case *parser.EcnKey:
	case *parser.EcnMatch:
	case *parser.EtypeKey:
	case *parser.EtypeMatch:
	case *parser.Expression:
	case *parser.FlowDirectionMatch:
	case *parser.IcmpMatch:
	case *parser.IfSpeedRangeMatch:
	case *parser.InterfaceMatch:
	case *parser.IPTosRangeMatch:
	case *parser.LocalPrefRangeMatch:
	case *parser.MedRangeMatch:
	case *parser.NetsizeRangeMatch:
	case *parser.NextHopAsnMatch:
	case *parser.NextHopMatch:
	case *parser.NormalizedMatch:
	case *parser.Number:
	case *parser.PacketRangeMatch:
	case *parser.PassesThroughListMatch:
	case *parser.PortRangeMatch:
	case *parser.PpsRangeMatch:
	case *parser.ProtoKey:
	case *parser.ProtoMatch:
	case *parser.RangeEnd:
	case *parser.RegularMatchGroup:
	case *parser.RemoteCountryMatch:
	case *parser.RouterMatch:
	case *parser.RpkiKey:
	case *parser.RpkiMatch:
	case *parser.SamplingRateRangeMatch:
	case *parser.Statement:
	case *parser.StatusKey:
	case *parser.StatusMatch:
	case *parser.String:
	case *parser.TcpFlagsKey:
	case *parser.TcpFlagsMatch:
	case *parser.VrfRangeMatch:
	default:
		return fmt.Errorf("Encountered unknown node type: %T", node)
	}

	err := next() // descend to child nodes
	if err != nil {
		return err
	}

	// After processing all children...
	switch node := n.(type) {
	case *parser.Address:
	case *parser.AddressMatch:
	case *parser.AsnRangeMatch:
	case *parser.Boolean:
	case *parser.BpsRangeMatch:
	case *parser.ByteRangeMatch:
	case *parser.CidRangeMatch:
	case *parser.DirectionalMatchGroup:
	case *parser.DscpKey:
	case *parser.DscpMatch:
	case *parser.DurationRangeMatch:
	case *parser.EcnKey:
	case *parser.EcnMatch:
	case *parser.EtypeKey:
	case *parser.EtypeMatch:
	case *parser.Expression:
	case *parser.FlowDirectionMatch:
	case *parser.IcmpMatch:
	case *parser.IfSpeedRangeMatch:
	case *parser.InterfaceMatch:
	case *parser.IPTosRangeMatch:
	case *parser.LocalPrefRangeMatch:
	case *parser.MedRangeMatch:
	case *parser.NetsizeRangeMatch:
	case *parser.NextHopAsnMatch:
	case *parser.NextHopMatch:
	case *parser.NormalizedMatch:
	case *parser.Number:
	case *parser.PacketRangeMatch:
	case *parser.PassesThroughListMatch:
	case *parser.PortRangeMatch:
	case *parser.PpsRangeMatch:
	case *parser.ProtoKey:
	case *parser.ProtoMatch:
	case *parser.RangeEnd:
	case *parser.RegularMatchGroup:
	case *parser.RemoteCountryMatch:
	case *parser.RouterMatch:
	case *parser.RpkiKey:
	case *parser.RpkiMatch:
	case *parser.SamplingRateRangeMatch:
	case *parser.Statement:
	case *parser.StatusKey:
	case *parser.StatusMatch:
	case *parser.String:
	case *parser.TcpFlagsKey:
	case *parser.TcpFlagsMatch:
	case *parser.VrfRangeMatch:
	default:
		_ = node
	}
	return nil
}
