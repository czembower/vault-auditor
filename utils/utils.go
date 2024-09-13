package utils

import (
	"sync"
)

func SetNamespacePath(namespace string) string {
	var namespacePath string

	if namespace == "root" {
		namespacePath = ""
	} else {
		namespacePath = namespace + "/"
	}

	return namespacePath
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func AppendError(errMsg string, errors *[]string) {
	mu := sync.Mutex{}
	mu.Lock()
	*errors = append(*errors, errMsg)
	mu.Unlock()
}

func GetStringFromMap(m map[string]interface{}, key string) string {
	if value, ok := m[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}
