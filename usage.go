package main

import (
	"encoding/json"
	"strings"
)

type usageData struct {
	DistinctEntities json.Number `json:"distinctEntities,omitempty"`
	Clients          json.Number `json:"clients,omitempty"`
	NonEntityClients json.Number `json:"nonEntityClients,omitempty"`
	SecretSyncs      json.Number `json:"secretSyncs,omitempty"`
	AcmeClients      json.Number `json:"acmeClients,omitempty"`
}

func (i *vaultInventory) getUsageData(c *clientConfig) {
	path := "sys/internal/counters/activity/monthly"
	activity, _ := c.Client.Read(c.Ctx, path)

	i.Usage.DistinctEntities = activity.Data["distinct_entities"].(json.Number)
	i.Usage.Clients = activity.Data["clients"].(json.Number)
	i.Usage.NonEntityClients = activity.Data["non_entity_clients"].(json.Number)
	i.Usage.SecretSyncs = activity.Data["secret_syncs"].(json.Number)
	i.Usage.AcmeClients = activity.Data["acme_clients"].(json.Number)

	namespaceUsage := activity.Data["by_namespace"].([]interface{})
	for _, namespaceData := range namespaceUsage {
		for idx, namespace := range i.Namespaces {
			discoveredName := namespaceData.(map[string]interface{})["namespace_path"].(string)
			if discoveredName == "" {
				discoveredName = "root"
			}
			if strings.HasPrefix(discoveredName, namespace.Name) {
				subData := namespaceData.(map[string]interface{})["counts"]
				namespace.Usage.DistinctEntities = subData.(map[string]interface{})["distinct_entities"].(json.Number)
				namespace.Usage.Clients = subData.(map[string]interface{})["clients"].(json.Number)
				namespace.Usage.NonEntityClients = subData.(map[string]interface{})["non_entity_clients"].(json.Number)
				namespace.Usage.SecretSyncs = subData.(map[string]interface{})["secret_syncs"].(json.Number)
				namespace.Usage.AcmeClients = subData.(map[string]interface{})["acme_clients"].(json.Number)
			}
			i.Namespaces[idx] = namespace
		}
	}
}
