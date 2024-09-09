package main

import (
	"fmt"
	"strings"
	"sync"
)

func (i *vaultInventory) scanEngines(c *clientConfig, namespace string) {
	namespacePath := setNamespacePath(namespace)
	wg := sync.WaitGroup{}
	var path string

	secretEnginesWithRole := strings.Split(secretEnginesWithRole, ", ")
	secretEnginesWithRoles := strings.Split(secretEnginesWithRoles, ", ")

	for nsIdx, ns := range i.Namespaces {
		if ns.Name == namespace {
			for seIdx, engine := range ns.SecretsEngines {
				wg.Add(1)
				go func(nsIdx int, seIdx int, engine secretsEngine) {
					defer wg.Done()
					if stringInSlice(engine.Type, secretEnginesWithRole) {
						path = namespacePath + engine.Path + "role"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, role := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].SecretsEngines[seIdx].Roles = append(i.Namespaces[nsIdx].SecretsEngines[seIdx].Roles, role.(string))
							}
						}
					}
					if stringInSlice(engine.Type, secretEnginesWithRoles) {
						path = namespacePath + engine.Path + "roles"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, role := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].SecretsEngines[seIdx].Roles = append(i.Namespaces[nsIdx].SecretsEngines[seIdx].Roles, role.(string))
							}
						}
					}
					if engine.Type == "kv" {
						if engine.Version == "2" {
							path = namespacePath + engine.Path + "metadata"
						} else {
							path = strings.TrimSuffix(namespacePath+engine.Path, "/")
						}
						i.Namespaces[nsIdx].SecretsEngines[seIdx].Secrets = walkKvPath(path, i.Namespaces[nsIdx], c)
						i.Namespaces[nsIdx].SecretsEngines[seIdx].ItemCount = len(i.Namespaces[nsIdx].SecretsEngines[seIdx].Secrets)
					}
				}(nsIdx, seIdx, engine)
			}
		}
	}
	wg.Wait()
}

func walkKvPath(path string, namespace namespaceInventory, c *clientConfig) []string {
	var kvPaths []string
	listResp, err := c.Client.List(c.Ctx, path)
	if err != nil {
		namespace.Errors = append(namespace.Errors, fmt.Sprintf("error listing path %s: %v", path, err))
	} else {
		for _, kvPath := range listResp.Data["keys"].([]interface{}) {
			kvPathString := kvPath.(string)
			if !strings.HasSuffix(kvPathString, "/") {
				kvPaths = append(kvPaths, strings.Replace(path+"/"+kvPathString, "/metadata", "", 1))
			} else {
				kvPathString = strings.TrimSuffix(kvPathString, "/")
				kvPaths = append(kvPaths, walkKvPath(path+"/"+kvPathString, namespace, c)...)
			}
		}
	}

	return kvPaths
}
