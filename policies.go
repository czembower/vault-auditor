package main

import (
	"fmt"
	"strings"

	"github.com/czembower/vault-auditor/utils"
)

type policy struct {
	Name  string   `json:"name,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (ns *namespaceInventory) scanPolicies(c *clientConfig) {
	namespacePath := utils.SetNamespacePath(ns.Name)
	path := namespacePath + "sys/policy"

	policyResp, err := c.Client.List(c.Ctx, path)
	if err != nil {
		utils.AppendError(fmt.Sprintf("error listing path %s: %v", path, err), &ns.Errors)
		return
	}

	policies, ok := policyResp.Data["policies"].([]interface{})
	if !ok {
		utils.AppendError(fmt.Sprintf("invalid format for policies at path %s", path), &ns.Errors)
		return
	}

	for _, data := range policies {
		if policyName, ok := data.(string); ok {
			ns.processPolicy(c, path, policyName)
		} else {
			utils.AppendError(fmt.Sprintf("invalid policy name format at path %s", path), &ns.Errors)
		}
	}
}

func (ns *namespaceInventory) processPolicy(c *clientConfig, basePath, policyName string) {
	var p policy
	p.Name = policyName

	policyPath := fmt.Sprintf("%s/%s", basePath, policyName)
	policyDetails, err := c.Client.Read(c.Ctx, policyPath)
	if err != nil {
		utils.AppendError(fmt.Sprintf("error reading path %s: %v", policyPath, err), &ns.Errors)
		return
	}

	if rules, ok := policyDetails.Data["rules"].(string); ok {
		p.Paths = extractPathsFromRules(rules)
	} else {
		utils.AppendError(fmt.Sprintf("invalid or missing rules for policy %s at path %s", policyName, policyPath), &ns.Errors)
	}

	ns.Policies = append(ns.Policies, p)
}

func extractPathsFromRules(rules string) []string {
	var paths []string
	rulesList := strings.Split(rules, "\n")

	for _, rule := range rulesList {
		if strings.HasPrefix(rule, "path") {
			pathParts := strings.SplitN(rule, "\"", 3)
			if len(pathParts) >= 2 {
				paths = append(paths, pathParts[1])
			}
		}
	}
	return paths
}
