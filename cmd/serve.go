package cmd

import (
	"rsig/internal/config"
	"rsig/server"

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
		config := config.Get()

		if port != 0 {
			config.HTTP.Port = port
		}

		if dbDsn != "" {
			config.DATABASE.DbDsn = dbDsn
		}

		if keystorePath != "" {
			config.VALIDATORS.KeyStorePasswordPath = keystorePasswordPath
		}

		if keystorePasswordPath != "" {
			config.VALIDATORS.KeyStorePasswordPath = keystorePasswordPath
		}

		return server.InitServer(config)
	},
}

func init() {
	serveCmd.Flags().StringVar(
		&keystorePath,
		"keystore-path",
		"",
		"Path to the V4 keystore file",
	)

	serveCmd.Flags().StringVar(
		&keystorePasswordPath,
		"keystore-password-path",
		"",
		"Path to the V4 keystore password file",
	)

	serveCmd.Flags().IntVar(
		&port,
		"port",
		0,
		"Port to listen on",
	)

	serveCmd.Flags().StringVar(
		&dbDsn,
		"db-dsn",
		"",
		"DSN to connect to the database",
	)
	rootCmd.AddCommand(serveCmd)
}
