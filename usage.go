package main

import (
	"encoding/json"
	"fmt"
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
	activity, err := c.Client.Read(c.Ctx, path)
	if err != nil || activity.Data == nil {
		appendError(fmt.Sprintf("error reading path %s: %v", path, err), &i.Errors)
		return
	}

	extractUsageData(activity.Data, i)

	if byNamespace, ok := activity.Data["by_namespace"].([]interface{}); ok {
		processNamespaceUsage(byNamespace, i)
	} else {
		appendError(fmt.Sprintf("invalid type for 'by_namespace' in path %s", path), &i.Errors)
	}
}

func extractUsageData(data map[string]interface{}, i *vaultInventory) {
	extractNumber := func(key string, dest *json.Number) {
		if v, ok := data[key]; ok {
			if num, ok := v.(json.Number); ok {
				*dest = num
			}
		}
	}

	extractNumber("distinct_entities", &i.Usage.DistinctEntities)
	extractNumber("clients", &i.Usage.Clients)
	extractNumber("non_entity_clients", &i.Usage.NonEntityClients)
	extractNumber("secret_syncs", &i.Usage.SecretSyncs)
	extractNumber("acme_clients", &i.Usage.AcmeClients)
}

func processNamespaceUsage(byNamespace []interface{}, i *vaultInventory) {
	for _, nsData := range byNamespace {
		nsMap, ok := nsData.(map[string]interface{})
		if !ok {
			appendError("invalid namespace data format", &i.Errors)
			continue
		}

		discoveredName := nsMap["namespace_path"].(string)
		if discoveredName == "" {
			discoveredName = "root"
		}

		for idx, namespace := range i.Namespaces {
			if strings.HasPrefix(discoveredName, namespace.Name) {
				updateNamespaceUsage(nsMap, &namespace)
				i.Namespaces[idx] = namespace
				break
			}
		}
	}
}

func updateNamespaceUsage(nsData map[string]interface{}, namespace *namespaceInventory) {
	if counts, ok := nsData["counts"].(map[string]interface{}); ok {
		extractNumber := func(key string, dest *json.Number) {
			if v, ok := counts[key]; ok {
				if num, ok := v.(json.Number); ok {
					*dest = num
				}
			}
		}

		extractNumber("distinct_entities", &namespace.Usage.DistinctEntities)
		extractNumber("clients", &namespace.Usage.Clients)
		extractNumber("non_entity_clients", &namespace.Usage.NonEntityClients)
		extractNumber("secret_syncs", &namespace.Usage.SecretSyncs)
		extractNumber("acme_clients", &namespace.Usage.AcmeClients)
	} else {
		appendError("invalid 'counts' data format in namespace usage", &namespace.Errors)
	}
}
