package configs

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// Config structure represent yaml config for did driver
type Config struct {
	Server struct {
		Port int    `mapstructure:"port"`
		Host string `mapstructure:"host"`
	} `mapstructure:"server"`
	// TODO (illia-korotia): array of networks?
	EthNetwork struct {
		Address string `mapstructure:"address"`
		URL     string `mapstructure:"url"`
	} `mapstructure:"ethereum"`
	Ens struct {
		Network string `mapstructure:"network"`
		Owner   string `mapstructure:"owner"`
	} `mapstructure:"ens"`
}

// ReadConfigFromFile parse config file
func ReadConfigFromFile(path string) (*Config, error) {

	viper.AddConfigPath("./configs")
	viper.SetConfigName(path)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, errors.Wrap(err, "Error reading config file")
	}

	config := &Config{}

	err = viper.Unmarshal(config)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing config file")
	}

	return config, nil
}
