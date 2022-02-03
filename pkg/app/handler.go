package app

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/services"
	core "github.com/iden3/go-iden3-core"
)

type DidDocumentHandler struct {
	DidDocumentService *services.DidDocumentServices
}

// Get a did document by a did identifier.
func (d *DidDocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	did, err := core.ParseDID(rawURL[len(rawURL)-1])
	if err != nil {
		log.Println("invalid did in request:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println("did from request:", did)

	state, err := d.DidDocumentService.GetDidDocument(r.Context(), did.ID)
	if err != nil {
		log.Println("invalid get did document:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("state from smart contract:", state)

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(state)
}

// GetByDomain get a did document by domain.
func (d *DidDocumentHandler) GetByDomain(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	domain := rawURL[len(rawURL)-1]

	state, err := d.DidDocumentService.ResolveDomain(r.Context(), domain)
	if err != nil {
		log.Println("invalid get did document:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("state from smart contract:", state)

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(state)
}
