package parser

import (
	"fmt"
	"testing"
)

func TestGrammarPrint(t *testing.T) {
	fmt.Println(parser.String())
}

func TestAccept(t *testing.T) {
	tests := []string{
		// syntax
		``,
		// address
		`address 10.0.0.1`,
		`src address 10.0.0.1`,
		`address 255.255.255.255`,
		`dst address 255.255.255.255`,
		`address 2001:db8::1`,
		`src address 2001:db8::1`,
		`address 2001:db8:efef:affe::1`,
		`dst address 2001:db8:efef:affe::1`,
		`address 1.0.0.1/0`,
		`src address 10.0.0.1/10`,
		`dst address 255.255.255.255/255`,
		`address 2001:db8::1/128`,
		`dst address 2001:db8:efef::affe:1/48`,
		`src address 2001:db8:efef::affe:1/0`,
		// port
		`src port 1`,
		`dst port 42`,
		`port 65535`,
		`port <1000`,
		`port >1000`,
		`src port 500-5000`,
		`port 1 -4`,
		`port 7-1`,
		`port 0xff2`,
		`src port 0b1-0x23`,
		// interface
		`src iface 1`,
		`src interface 4`,
		`not dst iface 42`,
		`dst iface 42`,
		`dst iface 42`,
		`dst iface name 'Te'`,
		`src iface desc 'hello'`,
		`src iface speed 123`,
		`dst iface speed >123`,
		`src iface speed 1-23`,
		// proto
		`not proto 1`,
		`proto 4`,
		// etype
		`etype 1`,
		`etype 0x800`,
		// composite
		`(proto 6 and port 456) or src iface 0 and address 1.1.1.1`,
	}

	for _, test := range tests {
		_, err := Parse(test)
		if err != nil {
			t.Errorf("Input `%s` failed with:\n%s\n", test, err)
		}
	}
}

func TestReject(t *testing.T) {
	tests := []string{
		// address
		`address 10.0.1`,
		`src address 10.0.0.1.3`,
		`address 255.255.255.256`,
		`dst address 255.257.255.255`,
		`address 2001:db8:::1`,
		`src address 2001:db8::1:`,
		`address 2001:db8:efef:affe:0:1`,
		`dst address 2001:db8:efef:affe:::`,
		`address 1.0.0.1/-0`,
		`src address 10.0.0.1//`,
		`dst address 255.255.255.257/255`,
		`not not port 4`,
		`dst iface id 'bla'`,
		`dst iface name 4`,
		`src iface desc "lksj'`,
	}

	for _, test := range tests {
		_, err := Parse(test)
		if err == nil {
			t.Errorf("Input `%s` did not fail.\n", test)
		}
	}
}
