package visitors

import (
	"fmt"
	"strings"

	"github.com/bwNetFlow/flowfilter/parser"
)

type Printer struct {
	output []string
}

func (p *Printer) Print() {
	fmt.Println(strings.Join(p.output, " "))
}

func (p *Printer) String() string {
	return strings.Join(p.output, " ")
}

func (p *Printer) Visit(n parser.Node, next func() error) error {
	// Before processing a node's children, do different things for
	// different types of nodes.
	// This 'before' part must cover all node types which are returned by
	// any other node's `children` method, as it's got a default clause to
	// annoy devs when the AST changes.

	switch node := n.(type) {
	case *parser.AddressMatch:
		// prepend keyword as this is a complex field
		p.output = append(p.output, "address")
		// print both fields
		if node.Mask != nil {
			p.output = append(p.output, fmt.Sprintf("%s/%d", *node.Address, *node.Mask))
		} else {
			p.output = append(p.output, fmt.Sprintf("%s", *node.Address))
		}
	case *parser.RegularMatchGroup: // nothing to be done, just visit children
	case *parser.Expression: // nothing to be done, just visit children
	case *parser.InterfaceMatch:
		// prepend keyword as this is a complex field
		p.output = append(p.output, fmt.Sprintf("interface %d", *node.SnmpId))
	case *parser.Statement:
		// in case it's a SubExpression, wrap it
		if node.SubExpression != nil {
			p.output = append(p.output, "(")
		} // else children will handle themselves
	case *parser.Boolean:
		// add a not keyword if we're true here
		if *node {
			p.output = append(p.output, "not")
		}
	case *parser.RangeEnd:
		// prepend the range symbol as this is the Upper field
		p.output = append(p.output, fmt.Sprintf("- %d", *node))
	case *parser.PortRangeMatch:
		// prepend keyword as this is a complex field
		p.output = append(p.output, "port")
	case *parser.Number:
		p.output = append(p.output, fmt.Sprintf("%d", *node))
	case *parser.String:
		p.output = append(p.output, string(*node))
	default:
		return fmt.Errorf("Encountered unknown node type: %T", node)
	}

	err := next() // descend to child nodes
	if err != nil {
		return err
	}

	// After processing all children, some node types might need to finish
	// some stuff. No default clause this time, all types we're covered the
	// first time.
	switch node := n.(type) {
	case *parser.Statement:
		if node.SubExpression != nil {
			p.output = append(p.output, ")")
		}
	}
	return nil
}
