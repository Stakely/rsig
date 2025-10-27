package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func Migrate(dsn, migrationsDir, direction string, steps int) error {
	if dsn == "" {
		return fmt.Errorf("no database DSN provided")
	}

	if direction != "up" && direction != "down" {
		return fmt.Errorf("direction must be 'up' or 'down', not '%s'", direction)
	}

	m, err := migrate.New(
		"file://"+migrationsDir,
		dsn,
	)
	if err != nil {
		return fmt.Errorf("cannot init migrate: %w", err)
	}
	defer func() {
		srcErr, dbErr := m.Close()
		if srcErr != nil {
			fmt.Println("migrate close (source):", srcErr)
		}
		if dbErr != nil {
			fmt.Println("migrate close (db):", dbErr)
		}
	}()

	switch direction {
	case "up":
		err = m.Up()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("error applying migrations up: %w", err)
		}
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("✔ No new migrations (ErrNoChange)")
		} else {
			fmt.Println("✔ Migrations applied (up)")
		}

	case "down":
		if steps <= 0 {
			return fmt.Errorf("steps should be > 0 when using direction 'down'")
		}
		err = m.Steps(-steps)
		if err != nil {
			return fmt.Errorf("error applying migrations down: %w", err)
		}
		fmt.Printf("✔ Migrations reverted (down %d step(s))\n", steps)
	}

	v, dirty, verr := m.Version()
	if verr == nil {
		fmt.Printf("Current version: %d (dirty=%v)\n", v, dirty)
	} else if errors.Is(verr, migrate.ErrNilVersion) {
		fmt.Println("Current version: None")
	} else {
		fmt.Printf("Cannot obtain current version: %v\n", verr)
	}

	return nil
}
