package main

import (
	"fmt"
	"strings"
	"sync"
)

func (i *vaultInventory) scanAuths(c *clientConfig, namespace string) {
	namespacePath := setNamespacePath(namespace)
	wg := sync.WaitGroup{}

	authMethodsWithRole := strings.Split(authMethodsWithRole, ", ")
	authMethodsWithRoles := strings.Split(authMethodsWithRoles, ", ")
	authMethodsWithCerts := strings.Split(authMethodsWithCerts, ", ")
	authMethodsWithGroups := strings.Split(authMethodsWithGroups, ", ")
	authMethodsWithUsers := strings.Split(authMethodsWithUsers, ", ")

	for nsIdx, ns := range i.Namespaces {
		if ns.Name == namespace {
			for amIdx, am := range ns.AuthMounts {
				wg.Add(1)
				go func(nsIdx int, amIdx int, am authMount) {
					defer wg.Done()
					if stringInSlice(am.Type, authMethodsWithRole) {
						path := namespacePath + "auth/" + am.Path + "role"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, role := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].AuthMounts[amIdx].Roles = append(i.Namespaces[nsIdx].AuthMounts[amIdx].Roles, role.(string))
							}
						}
					}
					if stringInSlice(am.Type, authMethodsWithRoles) {
						path := namespacePath + "auth/" + am.Path + "roles"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, role := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].AuthMounts[amIdx].Roles = append(i.Namespaces[nsIdx].AuthMounts[amIdx].Roles, role.(string))
							}
						}
					}
					if stringInSlice(am.Type, authMethodsWithCerts) {
						path := namespacePath + "auth/" + am.Path + "certs"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, cert := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].AuthMounts[amIdx].Certs = append(i.Namespaces[nsIdx].AuthMounts[amIdx].Certs, cert.(string))
							}
						}
					}
					if stringInSlice(am.Type, authMethodsWithGroups) {
						path := namespacePath + "auth/" + am.Path + "groups"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, group := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].AuthMounts[amIdx].Groups = append(i.Namespaces[nsIdx].AuthMounts[amIdx].Groups, group.(string))
							}
						}
					}
					if stringInSlice(am.Type, authMethodsWithUsers) {
						path := namespacePath + "auth/" + am.Path + "users"
						listResp, err := c.Client.List(c.Ctx, path)
						if err != nil {
							i.Namespaces[nsIdx].Errors = append(i.Namespaces[nsIdx].Errors, fmt.Sprintf("error listing path %s: %v", path, err))
						} else {
							for _, user := range listResp.Data["keys"].([]interface{}) {
								i.Namespaces[nsIdx].AuthMounts[amIdx].Users = append(i.Namespaces[nsIdx].AuthMounts[amIdx].Users, user.(string))
							}
						}
					}
				}(nsIdx, amIdx, am)
			}
		}
	}
	wg.Wait()
}
