package inventory

import (
	"fmt"
	"strings"
	"sync"

	"github.com/czembower/vault-auditor/client"
	"github.com/czembower/vault-auditor/models"
	"github.com/czembower/vault-auditor/utils"
	"github.com/hashicorp/vault-client-go"
)

const (
	authMethodsWithRole  = "approle, azure, jwt, kubernetes, oidc, oci, saml"
	authMethodsWithRoles = "aws, gcp, token, cf, alicloud"
	authMethodsWithCerts = "cert"
)

func (ns *NamespaceInventory) scanAuths(c *client.ClientConfig) {
	namespacePath := utils.SetNamespacePath(ns.inventory.Namespaces)
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}

	authMethodsWithRole := strings.Split(authMethodsWithRole, ", ")
	authMethodsWithRoles := strings.Split(authMethodsWithRoles, ", ")
	authMethodsWithCerts := strings.Split(authMethodsWithCerts, ", ")

	appendAuthData := func(amIdx int, item models.AuthRole, dataType string) {
		mu.Lock()
		switch dataType {
		case "roles":
			ns.AuthMounts[amIdx].Roles = append(ns.AuthMounts[amIdx].Roles, item)
		case "certs":
			ns.AuthMounts[amIdx].Certs = append(ns.AuthMounts[amIdx].Certs, item)
		}
		mu.Unlock()
	}

	sem := make(chan struct{}, c.MaxConcurrency)

	for amIdx, am := range ns.AuthMounts {
		wg.Add(1)
		sem <- struct{}{}
		go func(amIdx int, am models.AuthMount) {
			defer wg.Done()
			defer func() { <-sem }()
			localErrors := []string{}

			listAndProcess := func(key string, dataType string) {
				path := namespacePath + "auth/" + am.Path + key
				listResp, err := c.Client.List(c.Ctx, path)
				if err != nil {
					localErrors = append(localErrors, fmt.Sprintf("error listing path %s: %v", path, err))
					return
				}

				keys, ok := listResp.Data["keys"].([]interface{})
				if !ok {
					localErrors = append(localErrors, fmt.Sprintf("invalid response at path %s: missing keys", path))
					return
				}

				for _, keyItem := range keys {
					item, ok := keyItem.(string)
					if !ok {
						localErrors = append(localErrors, fmt.Sprintf("invalid key type at path %s", path))
						continue
					}

					roleData := getAuthRole(c, ns, am.Path, item, key)
					appendAuthData(amIdx, roleData, dataType)
				}
			}

			if utils.StringInSlice(am.Type, authMethodsWithRole) {
				listAndProcess("role", "roles")
			}
			if utils.StringInSlice(am.Type, authMethodsWithRoles) {
				listAndProcess("roles", "roles")
			}
			if utils.StringInSlice(am.Type, authMethodsWithCerts) {
				listAndProcess("certs", "certs")
			}

			mu.Lock()
			ns.Errors = append(ns.Errors, localErrors...)
			mu.Unlock()
		}(amIdx, am)
	}
	wg.Wait()
}

func getAuthRole(c *client.ClientConfig, namespace *models.NamespaceInventory, mount string, role string, rolePath string) models.AuthRole {
	var roleData models.AuthRole
	var policiesInt interface{}

	roleResp, err := c.Client.Read(c.Ctx, "auth/"+mount+rolePath+"/"+role, vault.WithNamespace(namespace.Name))
	if err != nil {
		namespace.Errors = append(namespace.Errors, fmt.Sprintf("error reading path %s: %v", "auth/"+mount+rolePath+"/"+role, err))
	} else {
		if v, ok := roleResp.Data["token_policies"]; ok {
			policiesInt = v.([]interface{})
		}
		if v, ok := roleResp.Data["allowed_policies"]; ok {
			policiesInt = v.([]interface{})
		}
	}

	if policiesInt == nil {
		roleData.Policies = []string{}
	} else {
		for _, policy := range policiesInt.([]interface{}) {
			roleData.Policies = append(roleData.Policies, policy.(string))
		}
	}
	roleData.Name = role

	return roleData
}
