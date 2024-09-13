package client

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault-client-go"
	"golang.org/x/time/rate"
)

const timeout = 10 * time.Second

type ClientConfig struct {
	Addr           string          `json:"addr,omitempty"`
	Token          string          `json:"token,omitempty"`
	TlsSkipVerify  bool            `json:"tlsSkipVerify,omitempty"`
	Client         *vault.Client   `json:"client,omitempty"`
	Ctx            context.Context `json:"ctx,omitempty"`
	MaxConcurrency int             `json:"maxConcurrency,omitempty"`
	RateLimit      int             `json:"rateLimit,omitempty"`
	ListSecrets    bool            `json:"listSecrets,omitempty"`
}

func BuildClient(c *ClientConfig) (*vault.Client, error) {
	tls := vault.TLSConfiguration{}
	tls.InsecureSkipVerify = c.TlsSkipVerify
	limiter := rate.NewLimiter(rate.Limit(c.RateLimit), 2*c.RateLimit)

	client, err := vault.New(
		vault.WithAddress(c.Addr),
		vault.WithRequestTimeout(timeout),
		vault.WithRetryConfiguration(vault.RetryConfiguration{}),
		vault.WithTLS(tls),
		vault.WithRateLimiter(limiter),
	)
	if err != nil {
		return nil, fmt.Errorf("error initializing client for %s: %w", c.Addr, err)
	}

	client.SetToken(c.Token)
	c.Ctx = context.Background()

	return client, nil
}
