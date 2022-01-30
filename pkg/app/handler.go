package app

import (
	"log"
	"net/http"
	"strings"

	"github.com/iden3/driver-did-iden3/pkg/model"
	"github.com/iden3/driver-did-iden3/pkg/services"
	core "github.com/iden3/go-iden3-core"
)

type DidDocumentHandler struct {
	DidDocumentService *services.DidDocumentServices
}

// Get a did document by a did identifier.
func (d *DidDocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.Split(r.URL.Path, "/")
	did, err := model.NewDidFromString(rawURL[len(rawURL)-1])
	if err != nil {
		log.Println("invalid path in request:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println("did from request:", did)

	rawID, err := core.IDFromString(did.Identifier())
	if err != nil {
		log.Println("invalid format for identifier:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	state, err := d.DidDocumentService.GetDidDocument(r.Context(), rawID)
	if err != nil {
		log.Println("invalid get did document:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("state from smart contract:", state)

	w.WriteHeader(http.StatusOK)
	w.Write(state.Bytes())
}
