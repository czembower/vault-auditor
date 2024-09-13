package inventory

import (
	"fmt"
	"strings"
	"sync"

	"github.com/czembower/vault-auditor/client"
	"github.com/czembower/vault-auditor/models"
	"github.com/czembower/vault-auditor/utils"
)

const (
	secretEnginesWithRoles = "aws, azure, consul, database, kubernetes, pki, ssh"
	secretEnginesWithRole  = "nomad, terraform, transform,"
)

func ScanEngines(c *client.ClientConfig, namespace string, engineList []models.SecretsEngine) ([]models.SecretsEngine, []string) {
	var errors []string
	namespacePath := utils.SetNamespacePath(namespace)
	wg := sync.WaitGroup{}

	enginesWithRole := strings.Split(secretEnginesWithRole, ", ")
	enginesWithRoles := strings.Split(secretEnginesWithRoles, ", ")

	sem := make(chan struct{}, c.MaxConcurrency)

	for seIdx := range engineList {
		var engine models.SecretsEngine
		wg.Add(1)
		sem <- struct{}{}

		go func(seIdx int, engine models.SecretsEngine) {
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
						engine.Roles = append(engine.Roles, role.(string))
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
						engine.Roles = append(engine.Roles, role.(string))
					}
				}
			}

			if engine.Type == "kv" {
				if engine.Version == "2" {
					path = namespacePath + engine.Path + "metadata"
				} else {
					path = strings.TrimSuffix(namespacePath+engine.Path, "/")
				}
				// if c.ListSecrets {
				// 	walkKvPath(seIdx, path, c)
				// }
			}

			engine.ItemCount = len(engine.Secrets)
			errors = append(errors, localErrors...)

		}(seIdx, engine)
		engineList = append(engineList, engine)
	}

	wg.Wait()
	return engineList, errors
}

// func walkKvPath(seIdx int, path string, c *client.ClientConfig) ([]string, []string) {
// 	var kvPaths []string
// 	var errors []string

// 	listResp, err := c.Client.List(c.Ctx, path)
// 	if err != nil {
// 		errors = append(errors, fmt.Sprintf("error listing KV path %s: %v", path, err))
// 	} else {
// 		for _, kvPath := range listResp.Data["keys"].([]interface{}) {
// 			kvPathString := kvPath.(string)
// 			if !strings.HasSuffix(kvPathString, "/") {
// 				kvPaths = append(kvPaths, strings.Replace(path+"/"+kvPathString, "/metadata", "", 1))
// 			} else {
// 				kvPathString = strings.TrimSuffix(kvPathString, "/")
// 				kvPaths = append(kvPaths, walkKvPath(seIdx, path+"/"+kvPathString, c)...)
// 			}
// 		}
// 	}

// 	ns.SecretsEngines[seIdx].Secrets = kvPaths
// 	return kvPaths, errors
// }
