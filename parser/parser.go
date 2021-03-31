package parser

import (
	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
)

var (
	bpfLexer = stateful.MustSimple([]stateful.Rule{
		// syntax connectors and negators
		{Name: "Negation", Pattern: `\bnot\b`, Action: nil},
		{Name: "Conjunction", Pattern: `\b(and|or)\b`, Action: nil},
		// magic strings for different commands
		{Name: "EcnMagic", Pattern: `\b(ce|ect1|ect0)\b`, Action: nil},
		{Name: "DscpMagic", Pattern: `\b(default|besteffort)\b`, Action: nil},
		{Name: "EtypeMagic", Pattern: `\b(ipv6|ipv4|arp)\b`, Action: nil},
		{Name: "ProtoMagic", Pattern: `\b(icmp|tcp|udp|icmpv6|ipip|vrrp)\b`, Action: nil},
		{Name: "StatusMagic", Pattern: `\b(forwarded|dropped|acldeny|acldrop|unroutable|consumed|policerdrop)\b`, Action: nil},
		{Name: "TcpFlagMagic", Pattern: `\b(fin|syn|rst|psh|ack|urg|synack|cwr|ece)\b`, Action: nil},
		// actual match keywords
		{Name: "Direction", Pattern: `\b(src|dst)\b`, Action: nil},
		{Name: "Match", Pattern: `\b(bytes|packets|port|asn|interface|iface|address|router|country|direction|duration|etype|proto|status|tcpflags|iptos|dscp|ecn|nexthop|netsize|vrf|samplingrate|cid|icmp|bps|pps)\b`, Action: nil},
		{Name: "Standalone", Pattern: `\b(incoming|outgoing|normalized)\b`, Action: nil},
		// subcommands
		{Name: "IfaceSubcommands", Pattern: `\b(name|desc|speed)\b`, Action: nil},
		{Name: "IcmpSubcommands", Pattern: `\b(type|code)\b`, Action: nil},
		// generic datatype-style tokens
		{Name: "CountryCode", Pattern: `\b[a-zA-Z]{2}\b`, Action: nil}, // needs to be after 'or' and 'ce'
		{Name: "Address", Pattern: `[1-9a-f][0-9a-f]*(\.|:)[0-9a-f.:]+`, Action: nil},
		{Name: "Number", Pattern: `[0-9a-fx]+`, Action: nil},
		{Name: "Unary", Pattern: `<|>`, Action: nil},
		{Name: "Symbol", Pattern: `-|/|\(|\)`, Action: nil},
		{Name: "String", Pattern: `'[^']*'|"[^"]*"`, Action: nil},
		{Name: "whitespace", Pattern: `[ \t]+`, Action: nil},
	})

	parser = participle.MustBuild(&Expression{},
		participle.Lexer(bpfLexer),
		participle.Unquote("String"),
	)
)

func Parse(input string) (*Expression, error) {
	expr := &Expression{}
	err := parser.ParseString("", input, expr)
	return expr, err
}
