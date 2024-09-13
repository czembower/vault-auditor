package main

import (
	"sync"
)

func setNamespacePath(namespace string) string {
	var namespacePath string

	if namespace == "root" {
		namespacePath = ""
	} else {
		namespacePath = namespace + "/"
	}

	return namespacePath
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func appendError(errMsg string, errors *[]string) {
	mu := sync.Mutex{}
	mu.Lock()
	*errors = append(*errors, errMsg)
	mu.Unlock()
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if value, ok := m[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}
