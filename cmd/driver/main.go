package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-iden3/pkg/app"
	"github.com/iden3/driver-did-iden3/pkg/app/configs"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
)

func main() {
	cfg, err := configs.ReadConfigFromFile()
	if err != nil {
		log.Fatalf("can't read config: %+v\n", err)
	}
	fmt.Printf("config: %+v", cfg)

	var r *ens.Registry
	if cfg.Ens.Network != "" {
		e, err := ethclient.Dial(string(cfg.Ens.URL))
		if err != nil {
			log.Fatal("can't connect to eth network:", err)
		}
		r, err = ens.NewRegistry(e, ens.ListNetworks[string(cfg.Ens.Network)])
		if err != nil {
			log.Fatal("can't create registry:", err)
		}
	}

	resolvers := services.NewChainResolvers()
	for prefix, settings := range cfg.Resolvers {
		resolver, err := eth.NewResolver(string(settings.NetworkURL), string(settings.ContractAddress))
		if err != nil {
			log.Fatalf("failed configure resolver for network '%s': %v", prefix, err)
		}
		resolvers.Add(prefix, resolver)
	}

	mux := app.Handlers{DidDocumentHandler: &app.DidDocumentHandler{
		DidDocumentService: services.NewDidDocumentServices(resolvers, r),
	},
	}

	server := http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           mux.Routes(),
		ReadHeaderTimeout: time.Second,
	}
	err = server.ListenAndServe()
	log.Fatal(err)
}
