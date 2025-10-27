package cmd

import (
	"fmt"
	"rsig/database"
	"rsig/internal/config"

	"github.com/spf13/cobra"
)

var (
	migrationsDir string
	direction     string
	steps         int
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long: `Run database migrations for rsig.

By default:
  - Uses the DSN from your config file (database.dsn).
  - Looks for migration files in ./database/sql.
  - Runs "up"

Examples:
  rsig migrate --config ./config_example.yml
  rsig migrate --config ./config_example.yml --direction down --steps 1
  rsig migrate --dir ./other_route/migrations --direction up
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Get()
		dsn := cfg.DATABASE.DbDsn
		if dsn == "" {
			return fmt.Errorf("no database DSN configured (database.dsn is empty)")
		}

		return database.Migrate(
			dsn,
			migrationsDir,
			direction,
			steps,
		)
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)

	migrateCmd.Flags().StringVar(
		&migrationsDir,
		"dir",
		"./database/sql",
		"Migrations folder (.up.sql / .down.sql)",
	)

	migrateCmd.Flags().StringVar(
		&direction,
		"direction",
		"up",
		"Migrations direction: up | down",
	)

	migrateCmd.Flags().IntVar(
		&steps,
		"steps",
		1,
		"Number of steps to go when --direction down is used",
	)
}
