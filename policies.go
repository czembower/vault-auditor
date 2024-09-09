package main

import (
	"fmt"
	"strings"
)

type policy struct {
	Name  string   `json:"name,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (i *vaultInventory) scanPolicies(c *clientConfig, namespace string) {
	namespacePath := setNamespacePath(namespace)

	for nsIdx, ns := range i.Namespaces {
		if ns.Name == namespace {
			path := namespacePath + "sys/policy"
			policyResp, err := c.Client.List(c.Ctx, path)
			if err != nil {
				i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
			} else {
				policyInt := policyResp.Data["policies"].([]interface{})
				for _, data := range policyInt {
					var p policy
					p.Name = data.(string)
					policyPaths, err := c.Client.Read(c.Ctx, path+"/"+p.Name)
					if err != nil {
						i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error reading path %s: %v", path+"/"+p.Name, err))
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
					i.Namespaces[nsIdx].Policies = append(i.Namespaces[nsIdx].Policies, p)
				}
			}
		}
	}
}
