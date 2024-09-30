package main

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

func (i *vaultInventory) postgresOutput(sqlConnectionString string) error {
	db, err := sql.Open("postgres", sqlConnectionString)
	if err != nil {
		return fmt.Errorf("sql.Open: %w", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		return fmt.Errorf("db.Ping: %w", err)
	}
	fmt.Println("Connected to database.")

	dropTableSQL := `DROP TABLE IF EXISTS secrets;`
	_, err = db.Exec(dropTableSQL)
	if err != nil {
		return fmt.Errorf("Error dropping table: %w", err)
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
		return fmt.Errorf("Error creating table: %w", err)
	}

	txn, err := db.Begin()
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	stmt, err := txn.Prepare(pq.CopyIn("secrets", "secret_path", "namespace", "engine_type", "engine_version", "engine_path", "current_version", "creation_time", "updated_time", "access_granting_policies", "namespace_roles_with_access_granting_policies"))
	if err != nil {
		return fmt.Errorf("%w", err)
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
		return fmt.Errorf("exec: %w: lastInsert: %b rowsAffected: %b", err, lastInsert, rowsAffected)
	}

	err = stmt.Close()
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	err = txn.Commit()
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}
