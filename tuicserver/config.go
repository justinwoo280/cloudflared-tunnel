package tuicserver

import (
	"encoding/json"
	"errors"
	"os"
)

type Config struct {
	Server           string   `json:"server"`
	CertPath         string   `json:"cert_path"`
	PrivateKey       string   `json:"private_key"`
	Password         string   `json:"password"`
	ALPN             []string `json:"alpn"`
	ZeroRTTHandshake bool     `json:"zero_rtt_handshake"`
	AuthTimeout      int      `json:"auth_timeout"`
	MaxIdleTime      int      `json:"max_idle_time"`
	MaxPacketSize    uint32   `json:"max_packet_size"`
}

func NewConfig() *Config {
	cfg := &Config{}
	cfg.SetDefaults()

	// Override with environment variables
	if server := os.Getenv("TUIC_SERVER"); server != "" {
		cfg.Server = server
	}
	if certPath := os.Getenv("TUIC_CERT_PATH"); certPath != "" {
		cfg.CertPath = certPath
	}
	if privateKey := os.Getenv("TUIC_PRIVATE_KEY"); privateKey != "" {
		cfg.PrivateKey = privateKey
	}
	if password := os.Getenv("TUIC_PASSWORD"); password != "" {
		cfg.Password = password
	}

	return cfg
}

func NewConfigFromFile(path string) (*Config, error) {
	cfg := &Config{}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = cfg.Unmarshal(b)
	if err != nil {
		return nil, err
	}

	err = cfg.CheckValid()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Unmarshal(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *Config) SetDefaults() {
	c.Server = "0.0.0.0:8443"
	c.CertPath = ""
	c.PrivateKey = ""
	c.Password = ""
	c.ALPN = []string{"h3"}
	c.ZeroRTTHandshake = true
	c.AuthTimeout = 3
	c.MaxIdleTime = 30
	c.MaxPacketSize = 1400
}

func (c *Config) CheckValid() error {
	if c.Server == "" {
		return errors.New("tuic server address is empty")
	}

	if c.Password == "" {
		return errors.New("tuic password is empty")
	}

	if c.CertPath == "" {
		return errors.New("tuic cert path is empty")
	}

	if c.PrivateKey == "" {
		return errors.New("tuic private key is empty")
	}

	if c.AuthTimeout <= 0 {
		c.AuthTimeout = 3
	}

	if c.MaxIdleTime <= 0 {
		c.MaxIdleTime = 30
	}

	if c.MaxPacketSize <= 0 {
		c.MaxPacketSize = 1400
	}

	return nil
}
