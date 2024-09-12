package main

import (
	"fmt"
	"sync"
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
	namespacePath := setNamespacePath(ns.Name)
	path := namespacePath + "identity/entity/id"
	mu := sync.Mutex{}

	appendError := func(errMsg string) {
		mu.Lock()
		ns.Errors = append(ns.Errors, errMsg)
		mu.Unlock()
	}

	policyResp, err := c.Client.List(c.Ctx, path)
	if err != nil {
		appendError(fmt.Sprintf("error listing path %s: %v", path, err))
	} else {
		entityInt := policyResp.Data["keys"].([]interface{})
		for _, data := range entityInt {
			entityID := data.(string)
			var e entity
			e.ID = entityID
			entityData, err := c.Client.Read(c.Ctx, path+"/"+entityID)
			if err != nil {
				appendError(fmt.Sprintf("error reading path %s: %v", path+"/"+entityID, err))
			} else {
				e.Name = entityData.Data["name"].(string)
				policies := entityData.Data["policies"].([]interface{})
				for _, policy := range policies {
					e.Policies = append(e.Policies, policy.(string))
				}
				aliases := entityData.Data["aliases"].([]interface{})
				for _, aliasData := range aliases {
					var a alias
					a.ID = aliasData.(map[string]interface{})["id"].(string)
					a.Name = aliasData.(map[string]interface{})["name"].(string)
					a.MountPath = aliasData.(map[string]interface{})["mount_path"].(string)
					a.MountType = aliasData.(map[string]interface{})["mount_type"].(string)
					e.Aliases = append(e.Aliases, a)
				}
			}
			ns.Entities = append(ns.Entities, e)
		}
	}
}
