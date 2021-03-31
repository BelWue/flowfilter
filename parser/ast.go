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
	TcpFlag       *TcpFlagMatch           `| "tcpflags" @@`
	IPTos         *IPTosRangeMatch        `| "iptos" @@`
	Dscp          *DscpMatch              `| "dscp" @@`
	Ecn           *EcnMatch               `| "ecn" @@`
	SamplingRate  *SamplingRateRangeMatch `| "samplingrate" @@`
	Cid           *CidRangeMatch          `| "cid" @@`
	Icmp          *IcmpMatch              `| "icmp" @@`
	Bps           *BpsRangeMatch          `| "bps" @@`
	Pps           *PpsRangeMatch          `| "pps" @@`
}

func (o RegularMatchGroup) children() []Node {
	return []Node{o.Router, o.NextHop, o.Bytes, o.Packets, o.RemoteCountry,
		o.FlowDirection, o.Normalized, o.Duration, o.Etype, o.Proto,
		o.Status, o.TcpFlag, o.IPTos, o.Dscp, o.Ecn, o.SamplingRate,
		o.Cid, o.Icmp, o.Bps, o.Pps}
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

func (o EtypeMatch) children() []Node { return nil }

type EtypeKey Number

func (o *EtypeKey) Capture(values []string) error {
	switch values[0] {
	case "ipv4":
		*o = 0x0800
	case "arp":
		*o = 0x0806
	case "ipv6":
		*o = 0x86DD
	}
	return nil
}

type ProtoMatch struct {
	BranchNode
	Proto    *Number   `  @Number`
	ProtoKey *ProtoKey `| @ProtoMagic`
}

func (o ProtoMatch) children() []Node { return nil }

type ProtoKey Number

func (o *ProtoKey) Capture(values []string) error {
	switch values[0] {
	case "icmp":
		*o = 1
	case "tcp":
		*o = 6
	case "udp":
		*o = 17
	case "icmpv6":
		*o = 58
	case "ipip":
		*o = 94
	case "vrrp":
		*o = 112
	}
	return nil
}

type StatusMatch struct {
	BranchNode
	Status    *Number    `  @Number`
	StatusKey *StatusKey `| @StatusMagic`
}

func (o StatusMatch) children() []Node { return nil }

type StatusKey Number

func (o *StatusKey) Capture(values []string) error {
	// these are assumed as masks
	switch values[0] {
	case "forwarded":
		*o = 0b01000000
	case "dropped":
		*o = 0b10000000
	case "acldeny":
		*o = 0b10000001
	case "acldrop":
		*o = 0b10000010
	case "unroutable":
		*o = 0b10000011
	case "consumed":
		*o = 0b11000000
	case "policerdrop":
		*o = 0b10001010
	}
	// full list:
	// 0b00000000, Unknown
	// 0b01000000, Forwarded (Unknown)
	// 0b01000001, Forwarded (Fragmented)
	// 0b01000010, Forwarded (Not Fragmented)
	// 0b10000000, Dropped (Unknown)
	// 0b10000001, Dropped (ACL Deny)
	// 0b10000010, Dropped (ACL Drop)
	// 0b10000011, Dropped (Unroutable)
	// 0b10000100, Dropped (Adjacency)
	// 0b10000101, Dropped (Fragmented and DF set)
	// 0b10000110, Dropped (Bad Header Checksum)
	// 0b10000111, Dropped (Bad Total Length)
	// 0b10001000, Dropped (Bad Header Length)
	// 0b10001001, Dropped (Bad TTL)
	// 0b10001010, Dropped (Policer)
	// 0b10001011, Dropped (WRED)
	// 0b10001100, Dropped (RPF)
	// 0b10001101, Dropped (For Us)
	// 0b10001110, Dropped (Bad Output Interface)
	// 0b10001111, Dropped (Hardware)
	// 0b11000000, Consumed (Unknown)
	// 0b11000001, Consumed (Terminate Punt Adjacency)
	// 0b11000010, Consumed (Terminate Incomplete Adjacency)
	// 0b11000011, Consumed (Terminate For Us)
	return nil
}

type TcpFlagMatch struct {
	BranchNode
	TcpFlag    *Number     `  @Number`
	TcpFlagKey *TcpFlagKey `| @TcpFlagMagic`
}

func (o TcpFlagMatch) children() []Node { return nil }

type TcpFlagKey Number

func (o *TcpFlagKey) Capture(values []string) error {
	// these are assumed as masks
	switch values[0] {
	case "fin":
		*o = 0b000000001
	case "finack":
		*o = 0b000010001
	case "syn":
		*o = 0b000000010
	case "rst":
		*o = 0b000000100
	case "psh":
		*o = 0b000001000
	case "ack":
		*o = 0b000010000
	case "urg":
		*o = 0b000100000
	case "synack":
		*o = 0b000010010
	case "cwr":
		*o = 0b010000000
	case "ece":
		*o = 0b100000000
	}
	return nil
}

type IPTosRangeMatch struct{ NumericRange }

type DscpMatch struct {
	BranchNode
	Dscp    *Number  `  @Number` // first 6 bits of iptos
	DscpKey *DscpKey `| @DscpMagic`
}

func (o DscpMatch) children() []Node { return nil }

type DscpKey Number

func (o *DscpKey) Capture(values []string) error {
	// these are assumed as explicit
	switch values[0] {
	case "default":
		*o = 0b000000
	case "besteffort":
		*o = 0b000000
	}
	return nil
}

type EcnMatch struct {
	BranchNode
	Ecn    *Number `  @Number` // last 2 bits of iptos
	EcnKey *EcnKey `| @EcnMagic`
}

func (o EcnMatch) children() []Node { return nil }

type EcnKey Number

func (o *EcnKey) Capture(values []string) error {
	// these are assumed as explicit
	switch values[0] {
	case "ce":
		*o = 0b11
	case "ect1":
		*o = 0b01
	case "ect0":
		*o = 0b10
	}
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
	Vrf       *VrfRangeMatch     `| "vrf" @@ )`
}

func (o DirectionalMatchGroup) children() []Node {
	return []Node{o.Direction, o.Address, o.Interface, o.Port, o.Asn,
		o.Netsize, o.Vrf}
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
