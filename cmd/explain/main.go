package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/bwNetFlow/flowfilter/parser"
	"github.com/bwNetFlow/flowfilter/visitors"
)

func main() {
	// parse our arg
	expr, err := parser.Parse(strings.Join(os.Args[1:], " "))
	if err != nil {
		fmt.Println(err)
		return
	}
	printer := &visitors.Printer{}
	printer.Print(expr)
}
