package app

import "net/http"

type Handlers struct {
	DidDocumentHandler *DidDocumentHandler
}

func (s *Handlers) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/1.0/identifiers/", s.DidDocumentHandler.Get)
	mux.HandleFunc("/dns/", s.DidDocumentHandler.GetByDNSDomain)
	mux.HandleFunc("/ens/", s.DidDocumentHandler.GetByENSDomain)

	return mux
}
