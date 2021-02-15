package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config struct
type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
	JWT struct {
		SecretKey string `yaml:"secret-key"`
	} `yaml:"jwt"`
	Google struct {
		Drive struct {
			Credential    string `yaml:"credential"`
			SaveDirectory string `yaml:"save-directory"`
		} `yaml:"drive"`
	} `yaml:"google"`
	MongoDB struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Database string `yaml:"database"`
	} `yaml:"mongodb"`
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func validateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}

	return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
	var configPath string

	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")

	flag.Parse()

	if err := validateConfigPath(configPath); err != nil {
		return "", err
	}

	return configPath, nil
}
