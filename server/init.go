package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"rsig/internal/config"
	"rsig/internal/validator"
	"time"

	_ "github.com/lib/pq"
)

func InitServer(cfg config.Config) error {
	db, err := sql.Open("postgres", cfg.DATABASE.DbDsn)
	if err != nil {
		return fmt.Errorf("sql.Open failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database not reachable: %w", err)
	}

	log.Println("✅  Database connection established successfully")

	keys, err := validator.LoadValidatorKeys(cfg.VALIDATORS.KeystorePath, cfg.VALIDATORS.KeyStorePasswordPath)
	if err != nil {
		log.Fatalf("error loading keys: %v", err)
	}

	log.Printf("✅  Loaded %d validator keys into memory", len(keys))

	addr := fmt.Sprintf(":%d", cfg.HTTP.Port)
	mux := http.NewServeMux()
	registerRoutes(mux)
	log.Println("✅  Rsig listening on", addr)
	return http.ListenAndServe(addr, mux)
}
