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

type Config struct {
	HTTP HTTP `mapstructure:"http"`
}

var (
	once   sync.Once
	mu     sync.RWMutex
	c      = Config{HTTP: HTTP{Port: 8080}}
	inited bool
)

func Init(cfgFile string) (err error) {
	once.Do(func() {
		// Defaults
		viper.SetDefault("http.port", 8080)

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
