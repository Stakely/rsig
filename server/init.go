package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"rsig/internal/config"
	"rsig/internal/slashing"
	"rsig/internal/validator"
	"rsig/server/controllers"
	"time"

	_ "github.com/lib/pq"
)

type HttpApi struct {
	DB      *sql.DB
	Keys    map[string]*validator.ValidatorKey
	Handler http.Handler
}

func BuildHttpApi(ctx context.Context, cfg config.Config) (*HttpApi, func(context.Context) error, error) {
	// 1. Connect to the database
	db, err := sql.Open("postgres", cfg.DATABASE.DbDsn)
	if err != nil {
		return nil, nil, fmt.Errorf("sql.Open failed: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("database not reachable: %w", err)
	}

	log.Println("🛢️  Database reached out")

	// 2. Load keys
	keys, err := validator.LoadValidatorKeys(cfg.VALIDATORS.KeystorePath, cfg.VALIDATORS.KeyStorePasswordPath)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("load keys: %w", err)
	}

	log.Printf("🔐  Keys loaded from keystore: %d\n", len(keys))

	// 3. Slashing protection
	sp := slashing.NewSlashingProtection(db)

	// 4. Build mux server
	mux := http.NewServeMux()
	controllers.RegisterControllers(mux, keys, sp)

	app := &HttpApi{
		DB:      db,
		Keys:    keys,
		Handler: mux,
	}
	cleanup := func(ctx context.Context) error {
		return db.Close()
	}
	return app, cleanup, nil
}
