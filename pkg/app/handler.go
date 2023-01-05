package app

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/services"
)

type DidDocumentHandler struct {
	DidDocumentService *services.DidDocumentServices
}

// Get a did document by a did identifier.
func (d *DidDocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")

	state, err := d.DidDocumentService.GetDidDocument(r.Context(), rawURL[len(rawURL)-1])
	if err != nil {
		log.Printf("invalid get did document: %+v", err)
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
