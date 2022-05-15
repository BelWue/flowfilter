package parser

import (
	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

var (
	bpfLexer = lexer.MustSimple([]lexer.SimpleRule{
		// syntax connectors and negators
		{Name: "Negation", Pattern: `\bnot\b`},
		{Name: "Conjunction", Pattern: `\b(and|or)\b`},
		// magic strings for different commands
		{Name: "EcnMagic", Pattern: `\b(ce|ect1|ect0)\b`},
		{Name: "DscpMagic", Pattern: `\b(default|besteffort)\b`},
		{Name: "EtypeMagic", Pattern: `\b(ipv6|ipv4|arp)\b`},
		{Name: "ProtoMagic", Pattern: `\b(icmp|tcp|udp|icmpv6|ipip|vrrp)\b`},
		{Name: "StatusMagic", Pattern: `\b(forwarded|dropped|acldeny|acldrop|unroutable|consumed|policerdrop)\b`},
		{Name: "TcpFlagsMagic", Pattern: `\b(fin|syn|rst|psh|ack|urg|synack|cwr|ece)\b`},
		{Name: "RpkiMagic", Pattern: `\b(valid|invalid|notfound|unknown)\b`},
		// actual match keywords
		{Name: "Direction", Pattern: `\b(src|dst)\b`},
		{Name: "Match", Pattern: `\b(bytes|packets|port|asn|passes-through|interface|iface|address|router|country|direction|duration|etype|proto|status|tcpflags|iptos|dscp|ecn|nexthop|netsize|vrf|samplingrate|cid|icmp|bps|pps|med|localpref|rpki|nexthopasn)\b`},
		{Name: "Standalone", Pattern: `\b(incoming|outgoing|normalized)\b`},
		// subcommands
		{Name: "IfaceSubcommands", Pattern: `\b(name|desc|speed)\b`},
		{Name: "IcmpSubcommands", Pattern: `\b(type|code)\b`},
		// generic datatype-style tokens
		{Name: "CountryCode", Pattern: `\b[a-zA-Z]{2}\b`}, // needs to be after 'or' and 'ce'
		{Name: "Address", Pattern: `[1-9a-f][0-9a-f]*(\.|:)[0-9a-f.:]+`},
		{Name: "Number", Pattern: `[0-9a-fx]+`},
		{Name: "Unary", Pattern: `<|>`},
		{Name: "Symbol", Pattern: `-|/|\(|\)`},
		{Name: "String", Pattern: `'[^']*'|"[^"]*"`},
		{Name: "whitespace", Pattern: `[ \t]+`},
	})

	parser = participle.MustBuild(&Expression{},
		participle.Lexer(bpfLexer),
		participle.Unquote("String"),
	)

	EcnMagicMap = map[string]uint64{ // explicit
		"ce":   0b11,
		"ect1": 0b01,
		"ect0": 0b10,
	}
	EtypeMagicMap = map[string]uint64{ // explicit
		"ipv4": 0x0800,
		"arp":  0x0806,
		"ipv6": 0x86DD,
	}
	ProtoMagicMap = map[string]uint64{"icmp": 1, // explicit
		"tcp":    6,
		"udp":    17,
		"icmpv6": 58,
		"ipip":   94,
		"vrrp":   112}
	StatusMagicMap = map[string]uint64{ // mask
		"forwarded":   0b01000000,
		"dropped":     0b10000000,
		"acldeny":     0b10000001,
		"acldrop":     0b10000010,
		"unroutable":  0b10000011,
		"consumed":    0b11000000,
		"policerdrop": 0b10001010,
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
	}
	TcpFlagsMagicMap = map[string]uint64{ // mask
		"fin":    0b000000001,
		"finack": 0b000010001,
		"syn":    0b000000010,
		"rst":    0b000000100,
		"psh":    0b000001000,
		"ack":    0b000010000,
		"urg":    0b000100000,
		"synack": 0b000010010,
		"cwr":    0b010000000,
		"ece":    0b100000000,
	}
	DscpMagicMap = map[string]uint64{ // explicit
		"default": 0b000000,
	}
	RpkiMagicMap = map[string]uint64{"unknown": 0,
		"valid":    1,
		"notfound": 2,
		"invalid":  3,
	}
)

func Parse(input string) (*Expression, error) {
	expr := &Expression{}
	err := parser.ParseString("", input, expr)
	return expr, err
}
