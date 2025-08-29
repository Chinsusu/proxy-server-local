
package main

import (
	"fmt"
	"net"
	"os"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
)

func main() {
	cfg := config.LoadFwd()
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil { logging.Error.Println(err); os.Exit(1) }
	logging.Info.Printf("pgw-fwd listening on %s (skeleton)\n", cfg.Addr)
	for {
		c, err := ln.Accept()
		if err != nil { logging.Warn.Println(err); continue }
		go func(conn net.Conn) {
			defer conn.Close()
			fmt.Fprintln(conn, "pgw-fwd placeholder: upstream proxy dial not implemented yet")
		}(c)
	}
}
