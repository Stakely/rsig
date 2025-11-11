package cmd

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"rsig/internal/config"
	"rsig/server"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var (
	keystorePath         string
	keystorePasswordPath string
	port                 int
	dbDsn                string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Println("🚀  Initializing rsig HTTP server...")
		ctx := cmd.Context()
		cfg := config.Get()

		if port != 0 {
			cfg.HTTP.Port = port
		}
		if dbDsn != "" {
			cfg.DATABASE.DbDsn = dbDsn
		}
		if keystorePath != "" {
			cfg.VALIDATORS.KeystorePath = keystorePath
		}
		if keystorePasswordPath != "" {
			cfg.VALIDATORS.KeyStorePasswordPath = keystorePasswordPath
		}

		app, cleanup, err := server.BuildHttpApi(ctx, cfg)
		if err != nil {
			return err
		}
		defer cleanup(context.Background())

		srv := &http.Server{
			Addr:    ":" + strconv.Itoa(cfg.HTTP.Port),
			Handler: app.Handler,
		}

		go func() {
			log.Println("✅  Rsig listening on", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
			}
		}()

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		select {
		case <-stop:
			log.Println("🛑  signal received, shutting down...")
		case <-ctx.Done():
			log.Println("🛑  context canceled, shutting down...")
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		log.Println("👋  server stopped")
		return nil
	},
}

func init() {
	serveCmd.Flags().StringVar(&keystorePath, "keystore-path", "", "Path to the V4 keystore file")
	serveCmd.Flags().StringVar(&keystorePasswordPath, "keystore-password-path", "", "Path to the V4 keystore password file")
	serveCmd.Flags().IntVar(&port, "port", 0, "Port to listen on")
	serveCmd.Flags().StringVar(&dbDsn, "db-dsn", "", "DSN to connect to the database")
	rootCmd.AddCommand(serveCmd)
}
