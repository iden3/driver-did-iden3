package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/driver-did-iden3/pkg/app"
	"github.com/iden3/driver-did-iden3/pkg/app/configs"
	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/driver-did-iden3/pkg/services/blockchain/eth"
	"github.com/iden3/driver-did-iden3/pkg/services/ens"
	"github.com/iden3/driver-did-iden3/pkg/services/provers"
)

func main() {
	cfg, err := configs.ReadConfigFromFile()
	if err != nil {
		log.Fatalf("can't read config: %+v\n", err)
	}

	var r *ens.Registry
	if cfg.Ens.EthNodeURL != "" && cfg.Ens.Network != "" {
		e, err := ethclient.Dial(cfg.Ens.EthNodeURL)
		if err != nil {
			log.Fatal("can't connect to eth network:", err)
		}
		r, err = ens.NewRegistry(e, ens.ListNetworks[cfg.Ens.Network])
		if err != nil {
			log.Fatal("can't create registry:", err)
		}
	}
	var proverRegistry *services.DIDResolutionProverRegistry
	if cfg.WalletKey != "" {
		proverRegistry, err = initDIDResolutionProverRegistry(*cfg)
		if err != nil {
			log.Fatal("can't create registry:", err)
		}
	}

	mux := app.Handlers{DidDocumentHandler: &app.DidDocumentHandler{
		DidDocumentService: services.NewDidDocumentServices(initResolvers(), r, services.WithProvers(proverRegistry))},
	}

	server := http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:           addCORSHeaders(mux.Routes()),
		ReadHeaderTimeout: time.Second,
	}
	log.Printf("HTTP server start on '%s:%d'\n", cfg.Server.Host, cfg.Server.Port)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal("not expected exit from http listener:", err)
	}
}

func initResolvers() *services.ResolverRegistry {
	var path string
	if len(os.Args) > 2 {
		path = os.Args[1]
	}
	rs, err := configs.ParseResolversSettings(path)
	if err != nil {
		log.Fatal("can't read resolver settings:", err)
	}
	resolvers := services.NewChainResolvers()
	for chainName, chainSettings := range rs {
		for networkName, networkSettings := range chainSettings {
			prefix := fmt.Sprintf("%s:%s", chainName, networkName)
			resolver, err := eth.NewResolver(networkSettings.NetworkURL, networkSettings.ContractAddress)
			if err != nil {
				log.Fatalf("failed configure resolver for network '%s': %v", prefix, err)
			}
			resolvers.Add(prefix, resolver)
		}
	}

	return resolvers
}

func initDIDResolutionProverRegistry(cfg configs.Config) (*services.DIDResolutionProverRegistry, error) {

	proverRegistry := services.NewDIDResolutionProverRegistry()

	prover, err := provers.NewEIP712Prover(cfg.WalletKey)
	if err != nil {
		return nil, err
	}
	proverRegistry.Add(document.EthereumEip712SignatureProof2021Type, prover)

	return proverRegistry, nil
}

func addCORSHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
