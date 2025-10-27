package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"rsig/internal/config"
	"time"

	_ "github.com/lib/pq"
)

func InitServer(cfg config.Config) error {
	addr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	mux := http.NewServeMux()
	registerRoutes(mux)
	fmt.Println("Rsig listening on", addr)

	db, err := sql.Open("postgres", cfg.DATABASE.DbDsn)
	if err != nil {
		return fmt.Errorf("sql.Open failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database not reachable: %w", err)
	}

	return http.ListenAndServe(addr, mux)
}
