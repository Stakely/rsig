package controllers_test

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"rsig/internal/config"
	"rsig/server"

	"github.com/joho/godotenv"
)

func buildTestApi(t *testing.T) *httptest.Server {
	loadEnvTest(t)

	defaultDsn := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		dsn = defaultDsn
	}

	cfg := config.Config{
		DATABASE: config.DATABASE(struct{ DbDsn string }{
			DbDsn: dsn,
		}),
		VALIDATORS: config.VALIDATORS(struct {
			KeystorePath         string
			KeyStorePasswordPath string
		}{
			KeystorePath:         "./keystore",
			KeyStorePasswordPath: "./password",
		}),
	}

	app, cleanup, err := server.BuildHttpApi(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildHttpApi: %v", err)
	}
	t.Cleanup(func() { _ = cleanup(context.Background()) })

	ts := httptest.NewServer(app.Handler)
	return ts
}

func truncateTable(ctx context.Context, table string) error {
	db, err := sql.Open("postgres", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		return err
	}
	defer db.Close()

	query := "TRUNCATE TABLE " + table + " RESTART IDENTITY CASCADE;"
	_, err = db.ExecContext(ctx, query)
	return err
}

func loadEnvTest(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	dir := wd
	for {
		candidate := filepath.Join(dir, ".env.test")
		if _, err := os.Stat(candidate); err == nil {
			if err := godotenv.Overload(candidate); err != nil {
				t.Fatalf("Overload %s: %v", candidate, err)
			}

			return
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}
