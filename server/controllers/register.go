package controllers

import (
	"net/http"
	"rsig/internal/config"
	"rsig/internal/slashing"
	"rsig/internal/validator"
)

func RegisterControllers(mux *http.ServeMux, keys map[string]*validator.ValidatorKey, sp *slashing.SlashingProtection, cfg config.Config) {
	prefix := normalizePrefix(cfg.HTTP.ApiPrefix)
	mux.HandleFunc(prefix+"/healthz", func(w http.ResponseWriter, r *http.Request) {})
	signController(mux, keys, sp, cfg)
}

func normalizePrefix(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}
