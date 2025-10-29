package config

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type HTTP struct {
	Port int `mapstructure:"port"`
}

type DATABASE struct {
	DbDsn string `mapstructure:"dsn"`
}

type VALIDATORS struct {
	KeystorePath         string `mapstructure:"keystore_path"`
	KeyStorePasswordPath string `mapstructure:"keystore_password_path"`
}
type Config struct {
	HTTP       HTTP       `mapstructure:"http"`
	DATABASE   DATABASE   `mapstructure:"database"`
	VALIDATORS VALIDATORS `mapstructure:"validators"`
}

var (
	once   sync.Once
	mu     sync.RWMutex
	c      = Config{HTTP: HTTP{Port: 8080}, DATABASE: DATABASE{DbDsn: ""}, VALIDATORS: VALIDATORS{KeystorePath: "", KeyStorePasswordPath: ""}}
	inited bool
)

func Init(cfgFile string) (err error) {
	once.Do(func() {
		// Defaults
		viper.SetDefault("http.port", 8080)
		viper.SetDefault("database.dsn", "")
		viper.SetDefault("validators.keystore_path", "")
		viper.SetDefault("validators.keystore_password_path", "")

		// Config file
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		} else {
			viper.SetConfigName("config")
			viper.SetConfigType("yaml")
			viper.AddConfigPath(".")
			viper.AddConfigPath("$HOME/.config/rsig")
		}

		_ = viper.BindEnv("http.port", "HTTP_PORT")
		_ = viper.BindEnv("database.dsn", "DATABASE_DSN")
		_ = viper.BindEnv("validators.keystore_path", "VALIDATORS_KEYSTORE_PATH")
		_ = viper.BindEnv("validators.keystore_password_path", "VALIDATORS_KEYSTORE_PASSWORD_PATH")
		viper.AutomaticEnv()

		if e := viper.ReadInConfig(); e != nil {
			if _, ok := e.(viper.ConfigFileNotFoundError); !ok {
				err = e
				return
			}
		}

		if e := viper.Unmarshal(&c); e != nil {
			err = e
			return
		}
		inited = true

		viper.OnConfigChange(func(_ fsnotify.Event) {
			mu.Lock()
			defer mu.Unlock()
			_ = viper.Unmarshal(&c)
		})
		viper.WatchConfig()
	})
	return err
}

func Get() Config {
	mu.RLock()
	defer mu.RUnlock()
	return c
}

func Save() error {
	mu.RLock()
	defer mu.RUnlock()

	path := viper.ConfigFileUsed()
	if path == "" {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".config", "rsig")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path = filepath.Join(dir, "config.yaml")
		viper.SetConfigFile(path)
		return viper.WriteConfigAs(path)
	}
	return viper.WriteConfig()
}
