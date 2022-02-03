package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-iden3/pkg/app"
	"github.com/iden3/driver-did-iden3/pkg/app/configs"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
)

func main() {
	cfg, err := configs.ReadConfigFromFile("driver")
	if err != nil {
		log.Fatal("can't read config:", err)
	}

	e, err := ethclient.Dial(cfg.EthNetwork.URL)
	if err != nil {
		log.Fatal("can't connect to eth network:", err)
	}

	c, err := eth.NewStateContract(cfg.EthNetwork.Address, e)
	if err != nil {
		log.Fatal("can't create contract caller:", err)
	}

	r, err := ens.NewRegistry(e, ens.ListNetworks[cfg.Ens.Network])
	if err != nil {
		log.Fatal("can't create registry:", err)
	}

	mux := app.Handlers{DidDocumentHandler: &app.DidDocumentHandler{
		DidDocumentService: services.NewDidDocumentServices(c, r),
	},
	}

	err = http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port), mux.Routes())
	log.Fatal(err)
}
