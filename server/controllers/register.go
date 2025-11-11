package controllers

import (
	"net/http"
	"rsig/internal/validator"
)

func RegisterControllers(mux *http.ServeMux, keys map[string]*validator.ValidatorKey) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	signController(mux, keys)
}
