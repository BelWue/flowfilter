package visitors

import (
	"fmt"
	"github.com/bwNetFlow/flowfilter/parser"
	flow "github.com/bwNetFlow/protobuf/go"
	"net"
	"strings"
)

type Filter struct {
	flowmsg     *flow.FlowMessage
	__direction string // this is super hacky
}

func processNumericRange(node parser.NumericRange, compare uint64) (bool, error) {
	var err error
	if node.Lower != nil && node.Upper != nil {
		if uint64(*node.Lower) > uint64(*node.Upper) {
			err = fmt.Errorf("Bad range, %d - %d", *node.Lower, *node.Upper)
		}
		return uint64(*node.Lower) <= compare && compare <= uint64(*node.Upper), err
	} else {
		var unary string
		if node.Unary != nil {
			unary = string(*node.Unary)
		}
		switch unary {
		case "<":
			return compare < uint64(*node.Number), err
		case ">":
			return compare > uint64(*node.Number), err
		default:
			return compare == uint64(*node.Number), err
		}
	}
	return false, err
}

func (f *Filter) CheckFlow(expr *parser.Expression, flowmsg *flow.FlowMessage) (bool, error) {
	f.flowmsg = flowmsg                // provide current flow to actual Visitor
	err := parser.Visit(expr, f.Visit) // run the Visitor
	return expr.EvalResult, err
}

func (f *Filter) Visit(n parser.Node, next func() error) error {
	// Before processing a node's children.
	// This Visitor generally does nothing here, as we always want to know
	// our childrens evaluation first. This serves to throw an error when
	// new nodes haven't been added to this visitor yet.
	switch node := n.(type) {
	case *parser.AddressMatch:
	case *parser.Address:
	case *parser.AsnRangeMatch:
	case *parser.Boolean:
	case *parser.BpsRangeMatch:
	case *parser.ByteRangeMatch:
	case *parser.CidRangeMatch:
	case *parser.RegularMatchGroup:
	case *parser.DirectionalMatchGroup:
	case *parser.DurationRangeMatch:
	case *parser.EtypeMatch:
	case *parser.Expression:
	case *parser.FlowDirectionMatch:
	case *parser.IcmpMatch:
	case *parser.IfSpeedRangeMatch:
	case *parser.InterfaceMatch:
	case *parser.IPTosMatch:
	case *parser.NetsizeRangeMatch:
	case *parser.NextHopMatch:
	case *parser.NormalizedMatch:
	case *parser.Number:
	case *parser.PacketRangeMatch:
	case *parser.PortRangeMatch:
	case *parser.PpsRangeMatch:
	case *parser.ProtoMatch:
	case *parser.RangeEnd:
	case *parser.RemoteCountryMatch:
	case *parser.RouterMatch:
	case *parser.SamplingRateRangeMatch:
	case *parser.Statement:
	case *parser.StatusMatch:
	case *parser.String:
	case *parser.TcpFlagMatch:
	case *parser.VrfRangeMatch:
	default:
		return fmt.Errorf("Encountered unknown node type: %T", node)
	}

	err := next() // descend to child nodes
	if err != nil {
		return err
	}

	// After processing all children...
	// This Visitor does all its work here. Leaf nodes are skipped over.

	switch node := n.(type) {
	case *parser.AddressMatch:
		if node.Mask != nil {
			var mask net.IPMask
			if node.Address.To4() != nil {
				mask = net.CIDRMask(int(*node.Mask), 32)
			} else {
				mask = net.CIDRMask(int(*node.Mask), 128)
			}
			ipnet := &net.IPNet{*node.Address, mask}
			(*node).EvalResultSrc = ipnet.Contains(f.flowmsg.SrcAddr)
			(*node).EvalResultDst = ipnet.Contains(f.flowmsg.DstAddr)
		} else {
			(*node).EvalResultSrc = net.IP(f.flowmsg.SrcAddr).Equal(*node.Address)
			(*node).EvalResultDst = net.IP(f.flowmsg.DstAddr).Equal(*node.Address)
		}
	case *parser.AsnRangeMatch:
		(*node).EvalResultSrc, _ = processNumericRange(node.NumericRange, uint64(f.flowmsg.SrcAS))
		(*node).EvalResultDst, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.DstAS))
		if err != nil { // errs from above calls will be the same anyways
			return fmt.Errorf("Bad ASN range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.BpsRangeMatch:
		duration := f.flowmsg.TimeFlowEnd - f.flowmsg.TimeFlowStart
		if duration == 0 {
			duration += 1
		}
		bps := f.flowmsg.Bytes * 8 / duration
		(*node).EvalResult, err = processNumericRange(node.NumericRange, bps)
	case *parser.ByteRangeMatch:
		(*node).EvalResult, err = processNumericRange(node.NumericRange, f.flowmsg.Bytes)
		if err != nil {
			return fmt.Errorf("Bad byte size range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.CidRangeMatch:
		(*node).EvalResult, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.Cid))
		if err != nil {
			return fmt.Errorf("Bad cid range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.RegularMatchGroup:
		switch {
		case node.Router != nil:
			(*node).EvalResult = node.Router.EvalResult
		case node.NextHop != nil:
			(*node).EvalResult = node.NextHop.EvalResult
		case node.Bytes != nil:
			(*node).EvalResult = node.Bytes.EvalResult
		case node.Packets != nil:
			(*node).EvalResult = node.Packets.EvalResult
		case node.RemoteCountry != nil:
			(*node).EvalResult = node.RemoteCountry.EvalResult
		case node.FlowDirection != nil:
			(*node).EvalResult = node.FlowDirection.EvalResult
		case node.Normalized != nil:
			(*node).EvalResult = node.Normalized.EvalResult
		case node.Duration != nil:
			(*node).EvalResult = node.Duration.EvalResult
		case node.Etype != nil:
			(*node).EvalResult = node.Etype.EvalResult
		case node.Proto != nil:
			(*node).EvalResult = node.Proto.EvalResult
		case node.Status != nil:
			(*node).EvalResult = node.Status.EvalResult
		case node.TcpFlag != nil:
			(*node).EvalResult = node.TcpFlag.EvalResult
		case node.IPTos != nil:
			(*node).EvalResult = node.IPTos.EvalResult
		case node.SamplingRate != nil:
			(*node).EvalResult = node.SamplingRate.EvalResult
		case node.Cid != nil:
			(*node).EvalResult = node.Cid.EvalResult
		case node.Icmp != nil:
			(*node).EvalResult = node.Icmp.EvalResult
		case node.Bps != nil:
			(*node).EvalResult = node.Bps.EvalResult
		case node.Pps != nil:
			(*node).EvalResult = node.Pps.EvalResult
		}
	case *parser.DirectionalMatchGroup:
		if node.Direction == nil {
			switch {
			case node.Address != nil:
				(*node).EvalResult = node.Address.EvalResultSrc || node.Address.EvalResultDst
			case node.Interface != nil:
				(*node).EvalResult = node.Interface.EvalResultSrc || node.Interface.EvalResultDst
			case node.Port != nil:
				(*node).EvalResult = node.Port.EvalResultSrc || node.Port.EvalResultDst
			case node.Asn != nil:
				(*node).EvalResult = node.Asn.EvalResultSrc || node.Asn.EvalResultDst
			case node.Netsize != nil:
				(*node).EvalResult = node.Netsize.EvalResultSrc || node.Netsize.EvalResultDst
			case node.Vrf != nil:
				(*node).EvalResult = node.Vrf.EvalResultSrc || node.Vrf.EvalResultDst
			}
		} else if *node.Direction == "src" {
			switch {
			case node.Address != nil:
				(*node).EvalResult = node.Address.EvalResultSrc
			case node.Interface != nil:
				(*node).EvalResult = node.Interface.EvalResultSrc
			case node.Port != nil:
				(*node).EvalResult = node.Port.EvalResultSrc
			case node.Asn != nil:
				(*node).EvalResult = node.Asn.EvalResultSrc
			case node.Netsize != nil:
				(*node).EvalResult = node.Netsize.EvalResultSrc
			case node.Vrf != nil:
				(*node).EvalResult = node.Vrf.EvalResultSrc
			}
		} else if *node.Direction == "dst" {
			switch {
			case node.Address != nil:
				(*node).EvalResult = node.Address.EvalResultDst
			case node.Interface != nil:
				(*node).EvalResult = node.Interface.EvalResultDst
			case node.Port != nil:
				(*node).EvalResult = node.Port.EvalResultDst
			case node.Asn != nil:
				(*node).EvalResult = node.Asn.EvalResultDst
			case node.Netsize != nil:
				(*node).EvalResult = node.Netsize.EvalResultDst
			case node.Vrf != nil:
				(*node).EvalResult = node.Vrf.EvalResultDst
			}
		}
	case *parser.DurationRangeMatch:
		(*node).EvalResult, err = processNumericRange(node.NumericRange, f.flowmsg.TimeFlowEnd-f.flowmsg.TimeFlowStart)
		if err != nil {
			return fmt.Errorf("Bad duration range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.EtypeMatch:
		switch {
		case node.Etype != nil:
			(*node).EvalResult = f.flowmsg.Etype == uint32(*node.Etype)
		case node.EtypeKey != nil:
			(*node).EvalResult = f.flowmsg.Etype == uint32(*node.EtypeKey)
		}
	case *parser.Expression:
		switch {
		case node.Left == nil:
			(*node).EvalResult = true // empty filters return all flows
		case node.Conjunction == nil:
			(*node).EvalResult = node.Left.EvalResult
		case *node.Conjunction == "and":
			(*node).EvalResult = node.Left.EvalResult && node.Right.EvalResult
		case *node.Conjunction == "or":
			(*node).EvalResult = node.Left.EvalResult || node.Right.EvalResult
		}
	case *parser.FlowDirectionMatch:
		if *node.FlowDirection == "incoming" {
			(*node).EvalResult = f.flowmsg.FlowDirection == 0
		} else if *node.FlowDirection == "outgoing" {
			(*node).EvalResult = f.flowmsg.FlowDirection == 1
		}
	case *parser.IcmpMatch:
		switch {
		case node.Type != nil:
			(*node).EvalResult = uint32(*node.Type) == f.flowmsg.DstPort/256 && f.flowmsg.Proto == 1
		case node.Code != nil:
			(*node).EvalResult = uint32(*node.Code) == f.flowmsg.DstPort%256 && f.flowmsg.Proto == 1
		}
	case *parser.IfSpeedRangeMatch:
		(*node).EvalResultSrc, _ = processNumericRange(node.NumericRange, uint64(f.flowmsg.SrcIfSpeed)/1000)
		(*node).EvalResultDst, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.DstIfSpeed)/1000)
		if err != nil { // errs from above calls will be the same anyways
			return fmt.Errorf("Bad iface speed range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.InterfaceMatch:
		switch {
		case node.SnmpId != nil:
			(*node).EvalResultSrc = uint32(*node.SnmpId) == f.flowmsg.InIf
			(*node).EvalResultDst = uint32(*node.SnmpId) == f.flowmsg.OutIf
		case node.Name != nil:
			(*node).EvalResultSrc = strings.Contains(
				strings.ToLower(f.flowmsg.SrcIfName),
				strings.ToLower(string(*node.Name)),
			)
			(*node).EvalResultDst = strings.Contains(
				strings.ToLower(f.flowmsg.DstIfName),
				strings.ToLower(string(*node.Name)),
			)
		case node.Description != nil:
			(*node).EvalResultSrc = strings.Contains(
				strings.ToLower(f.flowmsg.SrcIfDesc),
				strings.ToLower(string(*node.Description)),
			)
			(*node).EvalResultDst = strings.Contains(
				strings.ToLower(f.flowmsg.DstIfDesc),
				strings.ToLower(string(*node.Description)),
			)
		case node.Speed != nil:
			(*node).EvalResultSrc = node.Speed.EvalResultSrc
			(*node).EvalResultDst = node.Speed.EvalResultDst
		}
	case *parser.IPTosMatch:
		switch {
		case node.IPTos != nil:
			(*node).EvalResult = f.flowmsg.IPTos == uint32(*node.IPTos)
		case node.IPTosKey != nil:
			(*node).EvalResult = f.flowmsg.IPTos&uint32(*node.IPTosKey) == uint32(*node.IPTosKey)
		}
	case *parser.NetsizeRangeMatch:
		(*node).EvalResultSrc, _ = processNumericRange(node.NumericRange, uint64(f.flowmsg.SrcNet))
		(*node).EvalResultDst, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.DstNet))
		if err != nil { // errs from above calls will be the same anyways
			return fmt.Errorf("Bad netsize range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.NextHopMatch:
		(*node).EvalResult = net.IP(f.flowmsg.NextHop).Equal(*node.Address)
	case *parser.NormalizedMatch:
		(*node).EvalResult = f.flowmsg.Normalized == 1
	case *parser.PacketRangeMatch:
		(*node).EvalResult, err = processNumericRange(node.NumericRange, f.flowmsg.Packets)
		if err != nil {
			return fmt.Errorf("Bad packet count range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.PortRangeMatch:
		(*node).EvalResultSrc, _ = processNumericRange(node.NumericRange, uint64(f.flowmsg.SrcPort))
		(*node).EvalResultDst, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.DstPort))
		if err != nil { // errs from above calls will be the same anyways
			return fmt.Errorf("Bad port range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.PpsRangeMatch:
		duration := f.flowmsg.TimeFlowEnd - f.flowmsg.TimeFlowStart
		if duration == 0 {
			duration += 1
		}
		pps := f.flowmsg.Packets / duration
		(*node).EvalResult, err = processNumericRange(node.NumericRange, pps)
	case *parser.ProtoMatch:
		switch {
		case node.Proto != nil:
			(*node).EvalResult = f.flowmsg.Proto == uint32(*node.Proto)
		case node.ProtoKey != nil:
			(*node).EvalResult = f.flowmsg.Proto == uint32(*node.ProtoKey)
		}
	case *parser.RemoteCountryMatch:
		(*node).EvalResult = strings.Contains(f.flowmsg.RemoteCountry, strings.ToUpper(string(*node.CountryCode)))
	case *parser.RouterMatch:
		(*node).EvalResult = net.IP(f.flowmsg.SamplerAddress).Equal(*node.Address)
	case *parser.SamplingRateRangeMatch:
		(*node).EvalResult, err = processNumericRange(node.NumericRange, f.flowmsg.SamplingRate)
		if err != nil {
			return fmt.Errorf("Bad samplingrate range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	case *parser.Statement:
		switch {
		case node.DirectionalMatch != nil:
			(*node).EvalResult = node.DirectionalMatch.EvalResult
		case node.RegularMatch != nil:
			(*node).EvalResult = node.RegularMatch.EvalResult
		case node.SubExpression != nil:
			(*node).EvalResult = node.SubExpression.EvalResult
		}
		if node.Negated != nil && *node.Negated == true {
			(*node).EvalResult = !(*node).EvalResult
		}
	case *parser.StatusMatch:
		switch {
		case node.Status != nil:
			(*node).EvalResult = f.flowmsg.ForwardingStatus == uint32(*node.Status)
		case node.StatusKey != nil:
			(*node).EvalResult = f.flowmsg.ForwardingStatus&uint32(*node.StatusKey) == uint32(*node.StatusKey)
		}
	case *parser.TcpFlagMatch:
		switch {
		case node.TcpFlag != nil:
			(*node).EvalResult = f.flowmsg.TCPFlags == uint32(*node.TcpFlag) && f.flowmsg.Proto == 6
		case node.TcpFlagKey != nil:
			(*node).EvalResult = f.flowmsg.TCPFlags&uint32(*node.TcpFlagKey) == uint32(*node.TcpFlagKey) && f.flowmsg.Proto == 6
		}
	case *parser.VrfRangeMatch:
		(*node).EvalResultSrc, _ = processNumericRange(node.NumericRange, uint64(f.flowmsg.IngressVrfID))
		(*node).EvalResultDst, err = processNumericRange(node.NumericRange, uint64(f.flowmsg.EgressVrfID))
		if err != nil { // errs from above calls will be the same anyways
			return fmt.Errorf("Bad ASN range, lower %d > upper %d",
				*node.Lower,
				*node.Upper)
		}
	}
	return nil
}
