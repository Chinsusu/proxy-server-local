package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/Chinsusu/proxy-server-local/pkg/nft"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

func main() {
	layer := flag.String("layer", "combined", "ruleset layer: base, dynamic, or combined")
	flag.Parse()

	config := nft.RenderConfig{
		LANInterface: "lan0",
		WANInterface: "wan0",
	}
	mappings := []types.MappingView{
		{
			ID: "mapped-client",
			Client: types.Client{
				ID:     "mapped-client",
				IPCidr: "10.44.0.2/32",
			},
			State:             "APPLIED",
			LocalRedirectPort: 15001,
		},
	}
	base, err := nft.RenderBase(nft.BaseConfig{
		LANInterface:       config.LANInterface,
		WANInterface:       config.WANInterface,
		ManagementTCPPorts: nft.DefaultManagementTCPPorts(),
	})
	if err != nil {
		log.Fatal(err)
	}
	dynamic, err := nft.RenderDynamic(config, mappings)
	if err != nil {
		log.Fatal(err)
	}

	switch *layer {
	case "base":
		fmt.Print(base)
	case "dynamic":
		fmt.Print(dynamic)
	case "combined":
		fmt.Print(base, dynamic)
	default:
		log.Fatalf("unknown layer %q", *layer)
	}
}
