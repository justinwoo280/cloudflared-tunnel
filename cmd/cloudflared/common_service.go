package main

import (
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"

	"github.com/cloudflare/cloudflared/cmd/cloudflared/cliutil"
	cfdflags "github.com/cloudflare/cloudflared/cmd/cloudflared/flags"
	"github.com/cloudflare/cloudflared/cmd/cloudflared/tunnel"
)

func buildArgsForToken(c *cli.Context, log *zerolog.Logger) ([]string, error) {
	token := c.Args().First()
	if _, err := tunnel.ParseToken(token); err != nil {
		return nil, cliutil.UsageError("Provided tunnel token is not valid (%s).", err)
	}

	args := []string{
		"tunnel", "run", "--token", token,
	}

	// Add --proxy flag if set
	if c.Bool(cfdflags.Proxy) {
		args = append(args, "--"+cfdflags.Proxy)
	}

	return args, nil
}

func getServiceExtraArgsFromCliArgs(c *cli.Context, log *zerolog.Logger) ([]string, error) {
	if c.NArg() > 0 {
		// currently, we only support extra args for token
		return buildArgsForToken(c, log)
	} else {
		// empty extra args
		return make([]string, 0), nil
	}
}

// proxyFlag is the CLI flag for enabling the proxy server
var proxyFlag = &cli.BoolFlag{
	Name:    cfdflags.Proxy,
	Usage:   "Enable built-in proxy server (configure via UUID, PORT, MODE environment variables)",
	EnvVars: []string{"CLOUDFLARED_PROXY"},
	Value:   false,
}
