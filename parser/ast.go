package parser

import "net"

// Node is an interface implemented by all AST nodes
type Node interface {
	children() []Node
}

// Branch Nodes have this struct embedded, as these fields can be used to pass
// evaluation results from children.
type BranchNode struct {
	EvalResult    bool
	EvalResultSrc bool
	EvalResultDst bool
}

// The overall structure of this grammar. Expressions are made up of statements
// in conjunction with more expressions. A statement consists of any matcher or
// a subexpression in parenthesis and is optionally negated.
type Expression struct {
	BranchNode
	Left        *Statement  `(@@ (`
	Conjunction *String     `@Conjunction`
	Right       *Expression `@@ )?)?`
}

func (o Expression) children() []Node {
	return []Node{o.Left, o.Conjunction, o.Right}
}

type Statement struct {
	BranchNode
	Negated          *Boolean               `@Negation? (`
	DirectionalMatch *DirectionalMatchGroup `  @@`
	RegularMatch     *RegularMatchGroup     `| @@`
	SubExpression    *Expression            `| "(" @@ ")" )`
}

func (o Statement) children() []Node {
	return []Node{o.Negated, o.DirectionalMatch, o.RegularMatch,
		o.SubExpression}
}

// Basic data type nodes which are mostly just aliases
type Address net.IP

func (o Address) children() []Node { return nil }

type Boolean bool

func (o Boolean) children() []Node { return nil }

type String string

func (o String) children() []Node { return nil }

type Number uint64

func (o Number) children() []Node { return nil }

// FIXME: pseudo "negative" Number
// used by the printer visitor only, for emitting a "-" between children
type RangeEnd Number

func (o RangeEnd) children() []Node { return nil }

type NumericRange struct {
	BranchNode
	Lower  *Number   `(@Number`
	Upper  *RangeEnd `"-" @Number) |`
	Unary  *String   `( @Unary?`
	Number *Number   `  @Number )`
}

func (o NumericRange) children() []Node {
	return []Node{o.Lower, o.Upper, o.Unary, o.Number}
}

// Match Nodes are the actual sub commands, without their command word
// They are in turn organized into MatchGroups. There are Regular Matches and
// Directional Matches.

// Regular Matches:
// * anything that has further sub commands or accepts fancy data
// * no direction
// * several dedicated Match structs for different data types and sub commands
type RegularMatchGroup struct {
	BranchNode
	Router        *RouterMatch            `"router" @@`
	NextHop       *NextHopMatch           `| "nexthop" @@`
	Bytes         *ByteRangeMatch         `| "bytes" @@`
	Packets       *PacketRangeMatch       `| "packets" @@`
	RemoteCountry *RemoteCountryMatch     `| "country" @@`
	FlowDirection *FlowDirectionMatch     `| "direction"? @@`
	Normalized    *NormalizedMatch        `| ""? @@`
	Duration      *DurationRangeMatch     `| "duration" @@`
	Etype         *EtypeMatch             `| "etype" @@`
	Proto         *ProtoMatch             `| "proto" @@`
	Status        *StatusMatch            `| "status" @@`
	TcpFlags      *TcpFlagsMatch          `| "tcpflags" @@`
	IPTos         *IPTosRangeMatch        `| "iptos" @@`
	Dscp          *DscpMatch              `| "dscp" @@`
	Ecn           *EcnMatch               `| "ecn" @@`
	SamplingRate  *SamplingRateRangeMatch `| "samplingrate" @@`
	Icmp          *IcmpMatch              `| "icmp" @@`
	Bps           *BpsRangeMatch          `| "bps" @@`
	Pps           *PpsRangeMatch          `| "pps" @@`
	ViaAsn        *ViaAsnRangeMatch       `| "via" @@`
}

func (o RegularMatchGroup) children() []Node {
	return []Node{o.Router, o.NextHop, o.Bytes, o.Packets, o.RemoteCountry,
		o.FlowDirection, o.Normalized, o.Duration, o.Etype, o.Proto,
		o.Status, o.TcpFlags, o.IPTos, o.Dscp, o.Ecn, o.SamplingRate,
		o.Icmp, o.Bps, o.Pps, o.ViaAsn}
}

type RouterMatch struct {
	BranchNode
	Address *net.IP `@Address`
}

func (o RouterMatch) children() []Node { return nil }

type NextHopMatch struct {
	BranchNode
	Address *net.IP `@Address`
}

func (o NextHopMatch) children() []Node { return nil }

type ByteRangeMatch struct{ NumericRange }

type PacketRangeMatch struct{ NumericRange }

type RemoteCountryMatch struct {
	BranchNode
	CountryCode *String `@CountryCode`
}

func (o RemoteCountryMatch) children() []Node { return nil }

type FlowDirectionMatch struct {
	BranchNode
	FlowDirection *String `@("incoming"|"outgoing")`
}

func (o FlowDirectionMatch) children() []Node { return nil }

type NormalizedMatch struct {
	BranchNode
	Normalized bool `@"normalized"`
}

func (o NormalizedMatch) children() []Node { return nil }

type DurationRangeMatch struct{ NumericRange }

type EtypeMatch struct {
	BranchNode
	Etype    *Number   `  @Number`
	EtypeKey *EtypeKey `| @EtypeMagic`
}

func (o EtypeMatch) children() []Node {
	return []Node{o.Etype, o.EtypeKey}
}

type EtypeKey Number

func (o EtypeKey) children() []Node { return nil }

func (o *EtypeKey) Capture(values []string) error {
	*o = EtypeKey(EtypeMagicMap[values[0]])
	return nil
}

type ProtoMatch struct {
	BranchNode
	Proto    *Number   `  @Number`
	ProtoKey *ProtoKey `| @ProtoMagic`
}

func (o ProtoMatch) children() []Node {
	return []Node{o.Proto, o.ProtoKey}
}

type ProtoKey Number

func (o ProtoKey) children() []Node { return nil }

func (o *ProtoKey) Capture(values []string) error {
	*o = ProtoKey(ProtoMagicMap[values[0]])
	return nil
}

type StatusMatch struct {
	BranchNode
	Status    *Number    `  @Number`
	StatusKey *StatusKey `| @StatusMagic`
}

func (o StatusMatch) children() []Node {
	return []Node{o.Status, o.StatusKey}
}

type StatusKey Number

func (o StatusKey) children() []Node { return nil }

func (o *StatusKey) Capture(values []string) error {
	*o = StatusKey(StatusMagicMap[values[0]])
	return nil
}

type TcpFlagsMatch struct {
	BranchNode
	TcpFlags    *Number      `  @Number`
	TcpFlagsKey *TcpFlagsKey `| @TcpFlagsMagic`
}

func (o TcpFlagsMatch) children() []Node {
	return []Node{o.TcpFlags, o.TcpFlagsKey}
}

type TcpFlagsKey Number

func (o TcpFlagsKey) children() []Node { return nil }

func (o *TcpFlagsKey) Capture(values []string) error {
	*o = TcpFlagsKey(TcpFlagsMagicMap[values[0]])
	return nil
}

type IPTosRangeMatch struct{ NumericRange }

type DscpMatch struct {
	BranchNode
	Dscp    *Number  `  @Number` // first 6 bits of iptos
	DscpKey *DscpKey `| @DscpMagic`
}

func (o DscpMatch) children() []Node {
	return []Node{o.Dscp, o.DscpKey}
}

type DscpKey Number

func (o DscpKey) children() []Node { return nil }

func (o *DscpKey) Capture(values []string) error {
	*o = DscpKey(DscpMagicMap[values[0]])
	return nil
}

type EcnMatch struct {
	BranchNode
	Ecn    *Number `  @Number` // last 2 bits of iptos
	EcnKey *EcnKey `| @EcnMagic`
}

func (o EcnMatch) children() []Node {
	return []Node{o.Ecn, o.EcnKey}
}

type EcnKey Number

func (o EcnKey) children() []Node { return nil }

func (o *EcnKey) Capture(values []string) error {
	*o = EcnKey(EcnMagicMap[values[0]])
	return nil
}

type SamplingRateRangeMatch struct{ NumericRange }

type CidRangeMatch struct{ NumericRange }

type IcmpMatch struct {
	BranchNode
	Type *Number `  ( "type" @Number )`
	Code *Number `| ( "code" @Number )`
}

func (o IcmpMatch) children() []Node {
	return []Node{o.Type, o.Code}
}

type BpsRangeMatch struct{ NumericRange }

type PpsRangeMatch struct{ NumericRange }

type ViaAsnRangeMatch struct{ NumericRange }

// Directional Matches:
// * anything that has further sub commands or accepts fancy data
// * no direction
// * several dedicated Match structs for different data types and sub commands
type DirectionalMatchGroup struct {
	BranchNode
	Direction *String            `@Direction?`
	Address   *AddressMatch      `( "address" @@`
	Interface *InterfaceMatch    `| ("iface"|"interface") @@`
	Port      *PortRangeMatch    `| "port" @@`
	Asn       *AsnRangeMatch     `| "asn" @@`
	Netsize   *NetsizeRangeMatch `| "netsize" @@`
	Cid       *CidRangeMatch     `| "cid" @@`
	Vrf       *VrfRangeMatch     `| "vrf" @@ )`
}

func (o DirectionalMatchGroup) children() []Node {
	return []Node{o.Direction, o.Address, o.Interface, o.Port, o.Asn,
		o.Netsize, o.Cid, o.Vrf}
}

type AddressMatch struct {
	BranchNode
	Address *net.IP `@Address`
	Mask    *Number `( "/" @Number)?`
}

func (o AddressMatch) children() []Node { return nil }

type InterfaceMatch struct {
	BranchNode
	SnmpId      *Number            `  (   "id"? @Number )`
	Name        *String            `| ( "name"  @String )`
	Description *String            `| ( "desc"  @String )`
	Speed       *IfSpeedRangeMatch `| ("speed"  @@)`
}

func (o InterfaceMatch) children() []Node {
	return []Node{o.SnmpId, o.Name, o.Description, o.Speed}
}

type IfSpeedRangeMatch struct{ NumericRange }

type PortRangeMatch struct{ NumericRange }

type AsnRangeMatch struct{ NumericRange }

type NetsizeRangeMatch struct{ NumericRange }

type VrfRangeMatch struct{ NumericRange }
