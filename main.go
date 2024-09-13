package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/czembower/vault-auditor/client"
	"github.com/czembower/vault-auditor/inventory"
	"github.com/czembower/vault-auditor/models"
)

const (
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

func scan(c *client.ClientConfig, i models.VaultInventory) error {
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
			i = inventory.GetMounts(c, namespace)
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
			i.Namespaces[idx].scanEntities(c)
		}(idx)
	}
	wg.Wait()

	return nil
}

func main() {
	var c client.ClientConfig
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

	client, err := client.BuildClient(&c)
	if err != nil {
		log.Fatalf("buildClient: %v", err)
	}
	c.Client = client

	var i models.VaultInventory
	err = scan(&c, i)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	i.getUsageData(&c)

	jsonBytes, _ := json.MarshalIndent(i, "", "  ")
	fmt.Printf("%s\n", jsonBytes)
}
