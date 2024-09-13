package inventory

import (
	"fmt"
	"sync"

	"github.com/hashicorp/vault-client-go"
)

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
		appendError(fmt.Sprintf("error listing auth mounts for namespace %s: %v", namespace, err), &namespaceInventory.Errors)
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
		appendError(fmt.Sprintf("error listing secrets engines for namespace %s: %v", namespace, err), &namespaceInventory.Errors)
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
