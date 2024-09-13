package inventory

import (
	"fmt"
	"sync"

	"github.com/czembower/vault-auditor/client"
	"github.com/czembower/vault-auditor/models"
	"github.com/czembower/vault-auditor/utils"
	"github.com/hashicorp/vault-client-go"
)

func GetMounts(c *client.ClientConfig, namespace string) models.NamespaceInventory {
	var namespacePool = sync.Pool{
		New: func() interface{} {
			return &models.NamespaceInventory{}
		},
	}
	namespaceInventory := namespacePool.Get().(*models.NamespaceInventory)
	namespaceInventory.Name = namespace

	authMountsResponse, err := c.Client.Read(c.Ctx, "sys/auth", vault.WithNamespace(namespace))
	if err != nil {
		utils.AppendError(fmt.Sprintf("error listing auth mounts for namespace %s: %v", namespace, err), &namespaceInventory.Errors)
	}
	if authMountsResponse != nil {
		for x, config := range authMountsResponse.Data {
			var authMount models.AuthMount
			authMount.Path = x
			authMount.Type = config.(map[string]interface{})["type"].(string)
			namespaceInventory.AuthMounts = append(namespaceInventory.AuthMounts, authMount)
		}
	}

	secretsEnginesResponse, err := c.Client.Read(c.Ctx, "sys/mounts", vault.WithNamespace(namespace))
	if err != nil {
		utils.AppendError(fmt.Sprintf("error listing secrets engines for namespace %s: %v", namespace, err), &namespaceInventory.Errors)
	}
	if secretsEnginesResponse != nil {
		for x, config := range secretsEnginesResponse.Data {
			var secretsEngine models.SecretsEngine
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

	return *namespaceInventory
}
