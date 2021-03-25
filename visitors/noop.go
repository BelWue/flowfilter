package visitors

import (
	"fmt"
	"github.com/bwNetFlow/flowfilter/parser"
)

type Noop struct {
	output []string
}

func (noop *Noop) Visit(n parser.Node, next func() error) error {
	// Before processing a node's children.
	switch node := n.(type) {
	case *parser.AddressMatch:
	case *parser.RegularMatchGroup:
	case *parser.Expression:
	case *parser.InterfaceMatch:
	case *parser.Statement:
	case *parser.Boolean:
	case *parser.RangeEnd:
	case *parser.PortRangeMatch:
	case *parser.Number:
	case *parser.String:
	default:
		return fmt.Errorf("Encountered unknown node type: %T", node)
	}

	err := next() // descend to child nodes
	if err != nil {
		return err
	}

	// After processing all children...
	switch node := n.(type) {
	case *parser.AddressMatch:
	case *parser.RegularMatchGroup:
	case *parser.Expression:
	case *parser.InterfaceMatch:
	case *parser.Statement:
	case *parser.Boolean:
	case *parser.RangeEnd:
	case *parser.PortRangeMatch:
	case *parser.Number:
	case *parser.String:
	default:
		_ = node
	}
	return nil
}
