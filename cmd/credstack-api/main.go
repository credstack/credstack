package main

import (
	"github.com/credstack/credstack/internal/cli/api/root"
)

func main() {
	if err := root.NewRootCmd().Execute(); err != nil {
		panic(err)
	}
}
