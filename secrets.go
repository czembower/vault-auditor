package main

import (
	"fmt"
	"strings"
	"sync"
)

func (ns *namespaceInventory) scanEngines(c *clientConfig) {
	namespacePath := setNamespacePath(ns.Name)
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}

	enginesWithRole := strings.Split(secretEnginesWithRole, ", ")
	enginesWithRoles := strings.Split(secretEnginesWithRoles, ", ")

	sem := make(chan struct{}, c.MaxConcurrency)

	for seIdx := range ns.SecretsEngines {
		engine := &ns.SecretsEngines[seIdx]
		wg.Add(1)
		sem <- struct{}{}

		go func(seIdx int, engine *secretsEngine) {
			defer wg.Done()
			defer func() { <-sem }()
			localErrors := []string{}

			defer func() {
				if r := recover(); r != nil {
					localErrors = append(localErrors, fmt.Sprintf("recovered from panic in goroutine for engine index %d: %v", seIdx, r))
				}
			}()

			var path string
			if stringInSlice(engine.Type, enginesWithRole) {
				path = namespacePath + engine.Path + "role"
				listResp, err := c.Client.List(c.Ctx, path)
				if err != nil {
					localErrors = append(localErrors, fmt.Sprintf("error listing secrets engine `role` path %s: %v", path, err))
				} else {
					keys, ok := listResp.Data["keys"].([]interface{})
					if !ok {
						localErrors = append(localErrors, fmt.Sprintf("unexpected data format in list response for path %s", path))
						return
					}
					for _, role := range keys {
						mu.Lock()
						engine.Roles = append(engine.Roles, role.(string))
						mu.Unlock()
					}
				}
			}

			if stringInSlice(engine.Type, enginesWithRoles) {
				path = namespacePath + engine.Path + "roles"
				listResp, err := c.Client.List(c.Ctx, path)
				if err != nil {
					localErrors = append(localErrors, fmt.Sprintf("error listing secrets engine `roles` path %s: %v", path, err))
				} else {
					keys, ok := listResp.Data["keys"].([]interface{})
					if !ok {
						localErrors = append(localErrors, fmt.Sprintf("unexpected data format in list response for path %s", path))
						return
					}
					for _, role := range keys {
						mu.Lock()
						engine.Roles = append(engine.Roles, role.(string))
						mu.Unlock()
					}
				}
			}

			if engine.Type == "kv" {
				if engine.Version == "2" {
					path = namespacePath + engine.Path + "metadata"
				} else {
					path = strings.TrimSuffix(namespacePath+engine.Path, "/")
				}
				ns.walkKvPath(seIdx, path, c)
			}

			mu.Lock()
			engine.ItemCount = len(engine.Secrets)
			ns.Errors = append(ns.Errors, localErrors...)
			mu.Unlock()

		}(seIdx, engine)
	}

	wg.Wait()
}

func (ns *namespaceInventory) walkKvPath(seIdx int, path string, c *clientConfig) []string {
	var kvPaths []string
	listResp, err := c.Client.List(c.Ctx, path)
	if err != nil {
		ns.Errors = append(ns.Errors, fmt.Sprintf("error listing KV path %s: %v", path, err))
	} else {
		for _, kvPath := range listResp.Data["keys"].([]interface{}) {
			kvPathString := kvPath.(string)
			if !strings.HasSuffix(kvPathString, "/") {
				kvPaths = append(kvPaths, strings.Replace(path+"/"+kvPathString, "/metadata", "", 1))
			} else {
				kvPathString = strings.TrimSuffix(kvPathString, "/")
				kvPaths = append(kvPaths, ns.walkKvPath(seIdx, path+"/"+kvPathString, c)...)
			}
		}
	}

	ns.SecretsEngines[seIdx].Secrets = kvPaths
	return kvPaths
}
