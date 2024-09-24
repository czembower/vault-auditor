package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/czembower/vault-auditor/utils"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

type staticSecret struct {
	Path           string      `json:"path,omitempty"`
	CurrentVersion json.Number `json:"currentVersion,omitempty"`
	CreationTime   string      `json:"creationTime,omitempty"`
	UpdatedTime    string      `json:"updatedTime,omitempty"`
	Policies       []string    `json:"policies,omitempty"`
	Roles          []string    `json:"roles,omitempty"`
}

func (ns *namespaceInventory) scanEngines(c *clientConfig, i *vaultInventory) {
	namespacePath := utils.SetNamespacePath(ns.Name)
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
			if utils.StringInSlice(engine.Type, enginesWithRole) {
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

			if utils.StringInSlice(engine.Type, enginesWithRoles) {
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
					engine.Version = "1"
					path = strings.TrimSuffix(namespacePath+engine.Path, "/")
				}
				if c.ListSecrets {
					if c.TargetEngine != "" {
						target := strings.Split(c.TargetEngine, "/")
						if ns.Name != target[0] || ns.SecretsEngines[seIdx].Path != target[1]+"/" {
							return
						}
					}
					ns.walkKvPath(seIdx, path, c, i)
				}
			}

			mu.Lock()
			engine.ItemCount = len(engine.Secrets)
			ns.Errors = append(ns.Errors, localErrors...)
			mu.Unlock()

		}(seIdx, engine)
	}

	wg.Wait()
}

func (ns *namespaceInventory) walkKvPath(seIdx int, basepath string, c *clientConfig, i *vaultInventory) []staticSecret {
	var kvPaths []staticSecret

	listResp, err := c.Client.List(c.Ctx, basepath)
	if err != nil {
		ns.Errors = append(ns.Errors, fmt.Sprintf("error listing KV path %s: %v", basepath, err))
	} else {
		for _, kvPath := range listResp.Data["keys"].([]interface{}) {
			kvPathString := kvPath.(string)
			var secret staticSecret
			if !strings.HasSuffix(kvPathString, "/") {
				if strings.Contains(basepath, "/metadata") {
					secretMetadata, err := c.Client.Read(c.Ctx, basepath+"/"+kvPathString)
					if err != nil {
						ns.Errors = append(ns.Errors, fmt.Sprintf("error reading KV metadata for %s: %v", basepath+"/"+kvPathString, err))
					} else {
						secret.CurrentVersion = secretMetadata.Data["current_version"].(json.Number)
						secret.CreationTime = secretMetadata.Data["created_time"].(string)
						secret.UpdatedTime = secretMetadata.Data["updated_time"].(string)
					}
				}
				secret.Path = strings.Replace(basepath+"/"+kvPathString, "/metadata", "", 1)
				for _, policy := range ns.Policies {
					for _, policyPath := range policy.Paths {
						match := checkForPolicyMatch(ns.Name, policyPath, basepath+"/"+kvPathString)
						if match {
							secret.Policies = append(secret.Policies, policy.Name)
						}
					}
				}
				if ns.Name != "root" {
					for _, namespace := range i.Namespaces {
						if namespace.Name == "root" {
							for _, policy := range namespace.Policies {
								for _, policyPath := range policy.Paths {
									match := checkForPolicyMatch(namespace.Name, policyPath, basepath+"/"+kvPathString)
									if match {
										secret.Policies = append(secret.Policies, policy.Name+" (root)")
									}
								}
							}
						}
					}
				}
				for _, authMount := range ns.AuthMounts {
					for _, role := range authMount.Roles {
						for _, policy := range role.Policies {
							if utils.StringInSlice(policy, secret.Policies) {
								secret.Roles = append(secret.Roles, role.Name)
							}
						}
					}
				}
				kvPaths = append(kvPaths, secret)
			} else {
				kvPathString = strings.TrimSuffix(kvPathString, "/")
				kvPaths = append(kvPaths, ns.walkKvPath(seIdx, basepath+"/"+kvPathString, c, i)...)
			}
		}
	}

	ns.SecretsEngines[seIdx].Secrets = kvPaths
	return kvPaths
}

func checkForPolicyMatch(namespace, policyPath, secretPath string) bool {
	if namespace == "root" {
		match := strutil.GlobbedStringsMatch("/"+policyPath, "/"+strings.Replace(secretPath, "/metadata", "", 1))
		return match
	}
	match := strutil.GlobbedStringsMatch("/"+namespace+"/"+policyPath, "/"+strings.Replace(secretPath, "/metadata", "", 1))

	return match
}
