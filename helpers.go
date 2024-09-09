package main

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
