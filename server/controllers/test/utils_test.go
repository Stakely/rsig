package controllers_test

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"

	"rsig/internal/config"
	"rsig/server"
)

func buildTestApi(t *testing.T) *httptest.Server {
	// TODO: Connect to test database
	cfg := config.Config{
		DATABASE: config.DATABASE(struct{ DbDsn string }{
			DbDsn: "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable",
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
