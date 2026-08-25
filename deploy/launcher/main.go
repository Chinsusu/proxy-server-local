// pgw-release-launcher is the only supported production root entrypoint.
// Release automation must build it with CGO_ENABLED=0 and install it root-owned
// mode 0755. It clears the complete caller environment before starting Bash.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := launch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pgw-release-launcher: %v\n", err)
		os.Exit(126)
	}
}
