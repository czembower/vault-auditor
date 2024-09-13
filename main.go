package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault-client-go"
	"golang.org/x/time/rate"
)

const (
	timeout                = 3 * time.Second
	authMethodsWithRole    = "approle, azure, jwt, kubernetes, oidc, oci, saml"
	authMethodsWithRoles   = "aws, gcp, token, cf, alicloud"
	authMethodsWithCerts   = "cert"
	authMethodsWithGroups  = "ldap, okta, kerberos"
	authMethodsWithUsers   = "userpass, radius, okta, ldap"
	secretEnginesWithRoles = "aws, azure, consul, database, kubernetes, pki, ssh"
	secretEnginesWithRole  = "nomad, terraform, transform,"
	helpMessage            = `
vault-auditor is a tool to scan a Vault cluster for enabled auth methods, auth
method roles, secrets engines, static secret paths, entities, and policies. To
use vault-auditor, you must have a Vault token with a policy that allows listing
and reading various API paths. The capabilities required for auditing do not
include reading any secret data. See below for the recommended policy
definition.

Output is in JSON format. Errors encountered while scanning the Vault cluster
are included in this output. If your anticipate a large output, it is
recommended to redirect the output to a file.`
)

type clientConfig struct {
	Addr           string          `json:"addr,omitempty"`
	Token          string          `json:"token,omitempty"`
	TlsSkipVerify  bool            `json:"tlsSkipVerify,omitempty"`
	Client         *vault.Client   `json:"client,omitempty"`
	Ctx            context.Context `json:"ctx,omitempty"`
	MaxConcurrency int             `json:"maxConcurrency,omitempty"`
	RateLimit      int             `json:"rateLimit,omitempty"`
	ListSecrets    bool            `json:"listSecrets,omitempty"`
}

type vaultInventory struct {
	Namespaces []namespaceInventory `json:"namespaces,omitempty"`
	Usage      usageData            `json:"usage,omitempty"`
}

func (c *clientConfig) buildClient() (*vault.Client, error) {
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

func (i *vaultInventory) scan(c *clientConfig) error {
	namespacesResponse, err := c.Client.List(c.Ctx, "sys/namespaces")
	if err != nil {
		return fmt.Errorf("error listing namespaces: %w", err)
	}
	namespaceListInt := namespacesResponse.Data["keys"].([]interface{})
	namespaceList := make([]string, 0, len(namespaceListInt)+1)
	namespaceList = append(namespaceList, "root")

	for _, namespace := range namespaceListInt {
		namespaceList = append(namespaceList, strings.TrimSuffix(namespace.(string), "/"))
	}

	wg := sync.WaitGroup{}
	sem := make(chan struct{}, c.MaxConcurrency)

	for _, namespace := range namespaceList {
		wg.Add(1)
		sem <- struct{}{}
		go func(namespace string) {
			defer wg.Done()
			defer func() { <-sem }()
			i.getMounts(c, namespace)
		}(namespace)
	}
	wg.Wait()

	for idx := range i.Namespaces {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			i.Namespaces[idx].scanEngines(c)
			i.Namespaces[idx].scanAuths(c)
			i.Namespaces[idx].scanPolicies(c)
			// i.Namespaces[idx].scanEntities(c)
		}(idx)
	}
	wg.Wait()

	return nil
}

func main() {
	var c clientConfig
	flag.StringVar(&c.Addr, "address", "https://localhost:8200", "Vault cluster API address")
	flag.StringVar(&c.Token, "token", "", "Vault token with an appropriate audit policy")
	flag.IntVar(&c.MaxConcurrency, "maxConcurrency", 10, "Maximum number of concurrent requests to the Vault API")
	flag.IntVar(&c.RateLimit, "rateLimit", 100, "Maximum number of requests per second to the Vault API")
	flag.BoolVar(&c.TlsSkipVerify, "tlsSkipVerify", false, "Skip TLS verification of the Vault server's certificate")
	flag.BoolVar(&c.ListSecrets, "listSecrets", false, "List all secrets in the cluster (WARNING: this may be a large amount of data)")
	flag.CommandLine.Usage = func() {
		fmt.Println(helpMessage)
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage of vault-auditor:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	for _, arg := range os.Args {
		if arg == "--help" || arg == "--h" {
			flag.Usage()
			os.Exit(0)
		}
	}
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			log.Fatalf("Missing required flag: %s\n", f.Name)
		}
	})

	client, err := c.buildClient()
	if err != nil {
		log.Fatalf("buildClient: %v", err)
	}
	c.Client = client

	var i vaultInventory
	err = i.scan(&c)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	i.getUsageData(&c)

	jsonBytes, _ := json.MarshalIndent(i, "", "  ")
	fmt.Printf("%s\n", jsonBytes)
}
