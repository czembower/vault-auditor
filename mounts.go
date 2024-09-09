package main

import (
	"fmt"

	"github.com/hashicorp/vault-client-go"
)

type authMount struct {
	Path   string   `json:"path,omitempty"`
	Type   string   `json:"type,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Certs  []string `json:"certs,omitempty"`
}

type secretsEngine struct {
	Path      string   `json:"path,omitempty"`
	Type      string   `json:"type,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	Version   string   `json:"version,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
	ItemCount int      `json:"itemCount,omitempty"`
}

type namespaceInventory struct {
	Name           string          `json:"name,omitempty"`
	AuthMounts     []authMount     `json:"authMounts,omitempty"`
	SecretsEngines []secretsEngine `json:"secretsEngines,omitempty"`
	Policies       []policy        `json:"policies,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
}

func (i *vaultInventory) getMounts(c *clientConfig, namespace string) error {
	namespaceInventory := namespaceInventory{Name: namespace}

	authMountsResponse, err := c.Client.System.InternalUiListEnabledVisibleMounts(c.Ctx, vault.WithNamespace(namespace))
	if err != nil {
		namespaceInventory.Errors = append(namespaceInventory.Errors, fmt.Sprintf("error listing auth mounts for namespace %s: %v", namespace, err))
	}
	for x, config := range authMountsResponse.Data.Auth {
		var authMount authMount
		authMount.Path = x
		authMount.Type = config.(map[string]interface{})["type"].(string)
		namespaceInventory.AuthMounts = append(namespaceInventory.AuthMounts, authMount)
	}

	secretsEnginesResponse, err := c.Client.System.InternalUiListEnabledVisibleMounts(c.Ctx, vault.WithNamespace(namespace))
	if err != nil {
		namespaceInventory.Errors = append(namespaceInventory.Errors, fmt.Sprintf("error listing secrets engines for namespace %s: %v", namespace, err))
	}
	for x, config := range secretsEnginesResponse.Data.Secret {
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

	i.Namespaces = append(i.Namespaces, namespaceInventory)

	return nil
}
