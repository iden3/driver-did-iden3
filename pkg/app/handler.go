package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

type DidDocumentHandler struct {
	DidDocumentService *services.DidDocumentServices
}

// Get a did document by a did identifier.
func (d *DidDocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	opts, err := getResolverOpts(
		r.URL.Query().Get("state"),
		r.URL.Query().Get("gist"),
		r.URL.Query().Get("signature"),
		r.URL.Query().Get("alias"),
	)
	if err != nil {
		log.Println("invalid options query:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	did := rawURL[len(rawURL)-1]
	if opts.Alias != "" {
		// Resolve did by alias
		did, err = d.DidDocumentService.ResolveDIDByAlias(r.Context(), opts.Alias, did)
		if err != nil {
			log.Printf("failed resolve did by alias '%s': %v\n", opts.Alias, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	state, err := d.DidDocumentService.GetDidDocument(r.Context(), did, &opts)
	if errors.Is(err, core.ErrIncorrectDID) {
		log.Println("invalid did:", err)

	} else if err != nil {
		log.Printf("failed get did document: %+v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(state); err != nil {
		log.Println("failed write response")
	}
}

// GetByDNSDomain get a did document by domain.
func (d *DidDocumentHandler) GetByDNSDomain(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	domain := rawURL[len(rawURL)-1]

	state, err := d.DidDocumentService.ResolveDNSDomain(r.Context(), domain)
	if err != nil {
		log.Printf("invalid get did document: %+v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(state); err != nil {
		log.Println("failed write response")
	}
}

func (d *DidDocumentHandler) GetByENSDomain(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	domain := rawURL[len(rawURL)-1]

	state, err := d.DidDocumentService.ResolveENSDomain(r.Context(), domain)
	if err != nil {
		log.Printf("invalid get did document: %+v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(state); err != nil {
		log.Println("failed write response")
	}
}

func (d *DidDocumentHandler) GetGist(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	networkid := r.URL.Query().Get("networkid")
	if chain == "" || networkid == "" {
		log.Println("'chain' and 'networkid' should be set")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gistInfo, err := d.DidDocumentService.GetGist(r.Context(), chain, networkid, nil)
	if errors.Is(err, services.ErrNetworkIsNotSupported) {
		w.WriteHeader(http.StatusNotFound)
		log.Printf(`{"error":"resolver for '%s:%s' network not found"}`, chain, networkid)
		return
	} else if err != nil {
		log.Printf("failed get info about latest gist from network '%s:%s': %v\n", chain, networkid, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(gistInfo); err != nil {
		log.Println("failed write response")
	}
}

func (d *DidDocumentHandler) ResolveCredentialStatus(w http.ResponseWriter, r *http.Request) {
	var credentialStatus verifiable.CredentialStatus
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&credentialStatus)
	if err != nil {
		log.Printf("failed decode credential status body: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer func() {
		err := r.Body.Close()
		if err != nil {
			log.Printf("cannot close http body %v\n", err)
		}
	}()

	rawURL := strings.Split(r.URL.Path, "/")
	issuerDID := rawURL[len(rawURL)-1]
	status, err := d.DidDocumentService.ResolveCredentialStatus(r.Context(), issuerDID, credentialStatus)
	if err != nil {
		log.Printf("failed get credential status: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Println("failed write response")
	}
}

func getResolverOpts(state, gistRoot, signature, alias string) (ro services.ResolverOpts, err error) {
	if state != "" && gistRoot != "" {
		return ro, errors.New("'state' and 'gist root' cannot be used together")
	}
	if state != "" {
		s, err := merkletree.NewHashFromHex(state)
		if err != nil {
			return ro, fmt.Errorf("invalid state format: %v", err)
		}
		ro.State = s.BigInt()
	}
	if gistRoot != "" {
		g, err := merkletree.NewHashFromHex(gistRoot)
		if err != nil {
			return ro, fmt.Errorf("invalid gist root format: %v", err)
		}
		ro.GistRoot = g.BigInt()
	}
	if signature != "" && signature != string(document.EthereumEip712SignatureProof2021Type) {
		return ro, fmt.Errorf("not supported signature type %s", signature)
	}
	if signature != "" {
		ro.Signature = signature
	}
	if alias != "" {
		if signature != "" || state != "" || gistRoot != "" {
			return ro, errors.New("'alias' can only be used as single parameter")
		}
		ro.Alias = alias
	}
	return ro, nil
}
