package main

import (
	"fmt"
	"strings"
	"sync"
)

type policy struct {
	Name  string   `json:"name,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (ns *namespaceInventory) scanPolicies(c *clientConfig) {
	namespacePath := setNamespacePath(ns.Name)
	path := namespacePath + "sys/policy"
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
		policyInt := policyResp.Data["policies"].([]interface{})
		for _, data := range policyInt {
			var p policy
			p.Name = data.(string)
			policyPaths, err := c.Client.Read(c.Ctx, path+"/"+p.Name)
			if err != nil {
				appendError(fmt.Sprintf("error reading path %s: %v", path+"/"+p.Name, err))
			} else {
				var paths []string
				rules := policyPaths.Data["rules"].(string)
				rulesList := strings.Split(rules, "\n")
				for _, rule := range rulesList {
					if strings.HasPrefix(rule, "path") {
						cleanPath := strings.Split(rule, "path \"")[1]
						cleanPath = strings.Split(cleanPath, "\"")[0]
						paths = append(paths, cleanPath)
					}
				}
				p.Paths = paths
			}
			ns.Policies = append(ns.Policies, p)
		}
	}
}
