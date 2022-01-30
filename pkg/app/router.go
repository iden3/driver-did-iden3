package app

import "net/http"

type Handlers struct {
	DidDocumentHandler *DidDocumentHandler
}

func (s *Handlers) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.DidDocumentHandler.Get)

	return mux
}
