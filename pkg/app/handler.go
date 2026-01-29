package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

type acceptType string

const (
	acceptAny           acceptType = "*/*"
	acceptDIDJSON       acceptType = "application/did+json"
	acceptDIDLDJSON     acceptType = "application/did+ld+json"
	acceptDIDResolution acceptType = "application/did-resolution+json"
)

var supportedAccept = []acceptType{
	acceptDIDLDJSON,
	acceptDIDJSON,
	acceptDIDResolution,
	acceptAny,
}

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
	)
	if err != nil {
		log.Println("invalid options query:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// DidResolutionMetadata.ContentType should be included only if Accept header or query param is explicitly set
	acceptQuery := strings.TrimSpace(r.URL.Query().Get("accept"))
	acceptHeader := strings.TrimSpace(r.Header.Get("Accept"))
	explicitAccept :=
		acceptQuery != "" ||
			(acceptHeader != "" && acceptHeader != "*/*")

	accept := pickAccept(r)
	if accept == "" {
		http.Error(w, "not acceptable", http.StatusNotAcceptable)
		return
	}

	didResolution, err := d.DidDocumentService.GetDidDocument(r.Context(), rawURL[len(rawURL)-1], &opts)
	if err != nil {
		log.Printf("failed get did document: %+v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if accept == acceptAny {
		accept = acceptDIDResolution
	}

	switch accept {
	case acceptDIDResolution:
		w.Header().Set("Content-Type", string(acceptDIDResolution))
		w.WriteHeader(http.StatusOK)
		if explicitAccept && didResolution.DidResolutionMetadata != nil {
			didResolution.DidResolutionMetadata.ContentType = string(acceptDIDResolution)
		}
		if err := json.NewEncoder(w).Encode(didResolution); err != nil {
			log.Println("failed write response:", err)
		}
		return

	case acceptDIDJSON, acceptDIDLDJSON:
		w.Header().Set("Content-Type", string(accept))
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(didResolution.DidDocument); err != nil {
			log.Println("failed write response:", err)
		}
		return
	}

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(didResolution); err != nil {
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

func getResolverOpts(state, gistRoot, signature string) (ro services.ResolverOpts, err error) {
	if state != "" && gistRoot != "" {
		return ro, errors.New("'state' and 'gist root' cannot be used together")
	}
	if state != "" {
		s, err := merkletree.NewHashFromHex(state)
		if err != nil {
			return ro, fmt.Errorf("invalid state formant: %v", err)
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
	return
}

func pickAccept(r *http.Request) acceptType {
	if q := strings.TrimSpace(r.URL.Query().Get("accept")); q != "" {
		mt := normalizeMediaType(q)
		if isSupported(mt) {
			return mt
		}
		return ""
	}

	h := strings.TrimSpace(r.Header.Get("Accept"))
	if h == "" {
		return acceptAny
	}

	for _, p := range strings.Split(h, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		mt := normalizeMediaType(p)
		if isSupported(mt) {
			return mt
		}
	}
	return ""
}

func normalizeMediaType(v string) acceptType {
	v = strings.TrimSpace(v)
	v = stripParams(v)
	v = strings.ToLower(v)
	return acceptType(v)
}

func isSupported(mt acceptType) bool {
	for _, s := range supportedAccept {
		if mt == s {
			return true
		}
	}
	return false
}

func stripParams(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		return v[:i]
	}
	return v
}
