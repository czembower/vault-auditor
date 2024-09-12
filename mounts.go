package main

import (
	"fmt"
	"sync"

	"github.com/hashicorp/vault-client-go"
)

type namespaceInventory struct {
	Name           string          `json:"name,omitempty"`
	AuthMounts     []authMount     `json:"authMounts,omitempty"`
	SecretsEngines []secretsEngine `json:"secretsEngines,omitempty"`
	Entities       []entity        `json:"entities,omitempty"`
	Policies       []policy        `json:"policies,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
	Usage          usageData       `json:"usage,omitempty"`
}

type authMount struct {
	Path   string     `json:"path,omitempty"`
	Type   string     `json:"type,omitempty"`
	Roles  []authRole `json:"authRoles,omitempty"`
	Users  []string   `json:"users,omitempty"`
	Groups []string   `json:"groups,omitempty"`
	Certs  []authRole `json:"certs,omitempty"`
}

type secretsEngine struct {
	Path      string   `json:"path,omitempty"`
	Type      string   `json:"type,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	Version   string   `json:"version,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
	ItemCount int      `json:"itemCount,omitempty"`
}

func (i *vaultInventory) getMounts(c *clientConfig, namespace string) {
	var namespacePool = sync.Pool{
		New: func() interface{} {
			return &namespaceInventory{}
		},
	}
	namespaceInventory := namespacePool.Get().(*namespaceInventory)
	namespaceInventory.Name = namespace

	authMountsResponse, err := c.Client.Read(c.Ctx, "sys/auth", vault.WithNamespace(namespace))
	if err != nil {
		namespaceInventory.Errors = append(namespaceInventory.Errors, fmt.Sprintf("error listing auth mounts for namespace %s: %v", namespace, err))
	}
	if authMountsResponse != nil {
		for x, config := range authMountsResponse.Data {
			var authMount authMount
			authMount.Path = x
			authMount.Type = config.(map[string]interface{})["type"].(string)
			namespaceInventory.AuthMounts = append(namespaceInventory.AuthMounts, authMount)
		}
	}

	secretsEnginesResponse, err := c.Client.Read(c.Ctx, "sys/mounts", vault.WithNamespace(namespace))
	if err != nil {
		namespaceInventory.Errors = append(namespaceInventory.Errors, fmt.Sprintf("error listing secrets engines for namespace %s: %v", namespace, err))
	}
	if secretsEnginesResponse != nil {
		for x, config := range secretsEnginesResponse.Data {
			var secretsEngine secretsEngine
			secretsEngine.Path = x
			secretsEngine.Type = config.(map[string]interface{})["type"].(string)
			if v, ok := config.(map[string]interface{})["options"]; ok {
				if v != nil {
					if version, ok := v.(map[string]interface{})["version"]; ok {
						secretsEngine.Version = version.(string)
					}
				}
			}
			namespaceInventory.SecretsEngines = append(namespaceInventory.SecretsEngines, secretsEngine)
		}
	}

	i.Namespaces = append(i.Namespaces, *namespaceInventory)
}
