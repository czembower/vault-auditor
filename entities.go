package main

import (
	"fmt"
	"sync"

	"github.com/czembower/vault-auditor/utils"
)

type entity struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Policies []string `json:"policies,omitempty"`
	Aliases  []alias  `json:"aliases,omitempty"`
}

type alias struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	MountPath string `json:"mountPath,omitempty"`
	MountType string `json:"mountType,omitempty"`
}

func (ns *namespaceInventory) scanEntities(c *clientConfig) {
	namespacePath := utils.SetNamespacePath(ns.Name)
	path := namespacePath + "identity/entity/id"

	resp, err := c.Client.List(c.Ctx, path)
	if err != nil {
		utils.AppendError(fmt.Sprintf("error listing path %s: %v", path, err), &ns.Errors)
		return
	}

	keys, ok := resp.Data["keys"].([]interface{})
	if !ok {
		utils.AppendError(fmt.Sprintf("invalid data type for keys at path %s", path), &ns.Errors)
		return
	}

	wg := sync.WaitGroup{}
	sem := make(chan struct{}, c.MaxConcurrency)
	for _, data := range keys {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ns.getEntity(c, data.(string), path)
		}()
	}
}

func (ns *namespaceInventory) getEntity(c *clientConfig, id string, path string) {
	var e entity
	e.ID = id

	entityPath := path + "/" + e.ID
	entityData, err := c.Client.Read(c.Ctx, entityPath)
	if err != nil {
		utils.AppendError(fmt.Sprintf("error reading path %s: %v", entityPath, err), &ns.Errors)
		return
	}

	if name, ok := entityData.Data["name"].(string); ok {
		e.Name = name
	}

	if policies, ok := entityData.Data["policies"].([]interface{}); ok {
		e.Policies = make([]string, 0, len(policies))
		for _, policy := range policies {
			if policyStr, ok := policy.(string); ok {
				e.Policies = append(e.Policies, policyStr)
			} else {
				utils.AppendError(fmt.Sprintf("invalid policy type at path %s", entityPath), &ns.Errors)
			}
		}
	}

	if aliases, ok := entityData.Data["aliases"].([]interface{}); ok {
		e.Aliases = make([]alias, 0, len(aliases))
		for _, aliasData := range aliases {
			aliasMap, ok := aliasData.(map[string]interface{})
			if !ok {
				utils.AppendError(fmt.Sprintf("invalid alias data at path %s", entityPath), &ns.Errors)
				continue
			}

			a := alias{
				ID:        utils.GetStringFromMap(aliasMap, "id"),
				Name:      utils.GetStringFromMap(aliasMap, "name"),
				MountPath: utils.GetStringFromMap(aliasMap, "mount_path"),
				MountType: utils.GetStringFromMap(aliasMap, "mount_type"),
			}
			e.Aliases = append(e.Aliases, a)
		}
	}

	mu := sync.Mutex{}
	mu.Lock()
	ns.Entities = append(ns.Entities, e)
	mu.Unlock()
}
