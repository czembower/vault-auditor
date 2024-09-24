package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

func createFile(outputFormat string) (*os.File, error) {
	var fileName string

	switch outputFormat {
	case "json":
		fileName = "inventory.json"
	case "csv":
		fileName = "secrets.csv"
	default:
		return nil, fmt.Errorf("unsupported output format: %s", outputFormat)
	}

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return nil, err
	}

	return file, nil
}

func (i *vaultInventory) toCSV() {
	file, err := createFile("csv")
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Namespace", "Engine Type", "Engine Version", "Engine Path", "Secret Path", "Current Version", "Creation Time", "Updated Time", "Access-Granting Policies", "Namespace Roles with Access-Granting Policies"})

	for _, namespace := range i.Namespaces {
		for _, engine := range namespace.SecretsEngines {
			for _, secret := range engine.Secrets {
				writer.Write([]string{namespace.Name, engine.Type, engine.Version, engine.Path, secret.Path, string(secret.CurrentVersion), secret.CreationTime, secret.UpdatedTime, strings.Join(secret.Policies, ","), strings.Join(secret.Roles, ",")})
			}
		}
	}
}

func (i *vaultInventory) toJSON() {
	file, err := createFile("json")
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()

	jsonBytes, _ := json.MarshalIndent(i, "", "  ")
	file.Write(jsonBytes)
}
