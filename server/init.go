package server

import (
	"fmt"
	"net/http"
	"rsig/internal/config"
)

func InitServer(cfg config.Config) error {
	addr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	mux := http.NewServeMux()
	registerRoutes(mux)
	fmt.Println("Rsig listening on", addr)

	return http.ListenAndServe(addr, mux)
}
