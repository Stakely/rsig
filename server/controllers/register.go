package controllers

import (
	"net/http"
	"rsig/internal/slashing"
	"rsig/internal/validator"
)

func RegisterControllers(mux *http.ServeMux, keys map[string]*validator.ValidatorKey, sp *slashing.SlashingProtection) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	signController(mux, keys, sp)
}
