package main

import (
	"github.com/credstack/credstack/internal/cli/api/rootcmd"
)

func main() {
	if err := rootcmd.NewRootCmd().Execute(); err != nil {
		panic(err)
	}
}
