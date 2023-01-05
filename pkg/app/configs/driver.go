package configs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

type Secret string

func (s Secret) String() string {
	if len(s) == 0 {
		return ""
	}
	return "***"
}

func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"***"`), nil
}

// Config structure represent yaml config for did driver
type Config struct {
	Server struct {
		Port int    `envconfig:"PORT" default:"8080"`
		Host string `envconfig:"HOST" default:"localhost"`
	}
	// Example of envs:
	// export RESOLVERS= polygon:mumbai={"contractAddress":"0xf67...","url":"https://polygon-mumbai..."}
	Resolvers Resolvers `envconfig:"RESOLVERS" required:"true"`
	Ens       struct {
		URL     Secret `envconfig:"ENS_URL"`
		Network Secret `envconfig:"ENS_NETWORK"`
		Owner   Secret `envconfig:"ENS_OWNER"`
	}
}

type resolverSettings struct {
	ContractAddress Secret `json:"contractAddress"`
	NetworkURL      Secret `json:"url"`
}

type Resolvers map[string]resolverSettings

func (sd *Resolvers) Decode(value string) error {
	resolvers := map[string]resolverSettings{}
	pairs := strings.Split(value, ";")
	for _, pair := range pairs {
		settings := resolverSettings{}
		kvpair := strings.Split(pair, "=")
		if len(kvpair) != 2 {
			return fmt.Errorf("invalid map item: %q", pair)
		}
		err := json.Unmarshal([]byte(kvpair[1]), &settings)
		if err != nil {
			return fmt.Errorf("invalid map json: %w", err)
		}
		resolvers[kvpair[0]] = settings
	}
	*sd = resolvers
	return nil
}

// ReadConfigFromFile parse config file
func ReadConfigFromFile() (*Config, error) {
	cfg := &Config{}
	err := envconfig.Process("", cfg)
	return cfg, err
}
