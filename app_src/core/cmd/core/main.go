//go:build !android

package main

import (
	"core"
	"fmt"
	"os"
)

func main() {
	args := os.Args
	if len(args) <= 1 {
		fmt.Fprintln(os.Stderr, "Arguments error")
		os.Exit(1)
	}
	go core.ExitOnTermination()
	if args[1] == "-daemon" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Missing listen address")
			os.Exit(1)
		}
		if err := core.StartDaemonServer(args[2], os.Getenv("FLCLASH_CORE_TOKEN")); err != nil {
			fmt.Fprintf(os.Stderr, "daemon error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	core.StartServer(args[1])
}
