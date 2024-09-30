package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lib/pq"
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

func (i *vaultInventory) toJSON(stdout bool) {
	jsonBytes, _ := json.MarshalIndent(i, "", "  ")

	if !stdout {
		file, err := createFile("json")
		if err != nil {
			log.Fatalln(err)
		}
		defer file.Close()
		file.Write(jsonBytes)
	} else {
		fmt.Println(string(jsonBytes))
	}
}

func (i *vaultInventory) toSQL(sqlConnectionString string) {
	// Connect to SQL database and insert data
	db, err := sql.Open("postgres", sqlConnectionString)
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("db.Ping: %v", err)
	}
	fmt.Println("Connected to database.")

	dropTableSQL := `DROP TABLE IF EXISTS secrets;`
	_, err = db.Exec(dropTableSQL)
	if err != nil {
		log.Fatalf("Error dropping table: %s", err)
	}

	createTableSQL := `
	CREATE TABLE secrets (
		secret_path VARCHAR(255) PRIMARY KEY,
		namespace VARCHAR(100),
		engine_type VARCHAR(10),
		engine_version CHAR(1),
		engine_path VARCHAR(255),
		current_version VARCHAR(255),
		creation_time TIMESTAMP,
		updated_time TIMESTAMP,
		access_granting_policies TEXT,
		namespace_roles_with_access_granting_policies TEXT
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Error creating table: %s", err)
	}

	txn, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}

	stmt, err := txn.Prepare(pq.CopyIn("secrets", "secret_path", "namespace", "engine_type", "engine_version", "engine_path", "current_version", "creation_time", "updated_time", "access_granting_policies", "namespace_roles_with_access_granting_policies"))
	if err != nil {
		log.Fatal(err)
	}

	for _, namespace := range i.Namespaces {
		for _, engine := range namespace.SecretsEngines {
			for _, secret := range engine.Secrets {
				stmt.Exec(secret.Path, namespace.Name, engine.Type, engine.Version, engine.Path, string(secret.CurrentVersion), secret.CreationTime, secret.UpdatedTime, strings.Join(secret.Policies, ","), strings.Join(secret.Roles, ","))
			}
		}
	}

	exec, err := stmt.Exec()
	if err != nil {
		lastInsert, _ := exec.LastInsertId()
		rowsAffected, _ := exec.RowsAffected()
		log.Fatal("exec: ", err, lastInsert, rowsAffected)
	}

	err = stmt.Close()
	if err != nil {
		log.Fatal("close: ", err)
	}

	err = txn.Commit()
	if err != nil {
		log.Fatal("commit: ", err)
	}
	fmt.Println("Data inserted successfully.")
}
