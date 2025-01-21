package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/BelWue/flowfilter/parser"
	"github.com/BelWue/flowfilter/visitors"
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
