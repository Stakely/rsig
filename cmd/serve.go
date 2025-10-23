package cmd

import (
	"rsig/internal/config"
	"rsig/server"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := config.Get()
		return server.InitServer(config)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
