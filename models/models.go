package models

import "encoding/json"

type VaultInventory struct {
	Namespaces []NamespaceInventory `json:"namespaces,omitempty"`
	Usage      UsageData            `json:"usage,omitempty"`
	Errors     []string             `json:"errors,omitempty"`
}

type NamespaceInventory struct {
	Name           string          `json:"name,omitempty"`
	AuthMounts     []AuthMount     `json:"authMounts,omitempty"`
	SecretsEngines []SecretsEngine `json:"secretsEngines,omitempty"`
	Entities       []Entity        `json:"entities,omitempty"`
	Policies       []Policy        `json:"policies,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
	Usage          UsageData       `json:"usage,omitempty"`
}

type AuthMount struct {
	Path   string     `json:"path,omitempty"`
	Type   string     `json:"type,omitempty"`
	Roles  []AuthRole `json:"authRoles,omitempty"`
	Users  []string   `json:"users,omitempty"`
	Groups []string   `json:"groups,omitempty"`
	Certs  []AuthRole `json:"certs,omitempty"`
}

type SecretsEngine struct {
	Path      string   `json:"path,omitempty"`
	Type      string   `json:"type,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	Version   string   `json:"version,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
	ItemCount int      `json:"itemCount,omitempty"`
}

type Entity struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Policies []string `json:"policies,omitempty"`
	Aliases  []Alias  `json:"aliases,omitempty"`
}

type Alias struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	MountPath string `json:"mountPath,omitempty"`
	MountType string `json:"mountType,omitempty"`
}

type AuthRole struct {
	Name     string   `json:"name,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

type UsageData struct {
	DistinctEntities json.Number `json:"distinctEntities,omitempty"`
	Clients          json.Number `json:"clients,omitempty"`
	NonEntityClients json.Number `json:"nonEntityClients,omitempty"`
	SecretSyncs      json.Number `json:"secretSyncs,omitempty"`
	AcmeClients      json.Number `json:"acmeClients,omitempty"`
}

type Policy struct {
	Name  string   `json:"name,omitempty"`
	Paths []string `json:"paths,omitempty"`
}

func (v *VaultInventory) AddNamespace(ns NamespaceInventory) {
	v.Namespaces = append(v.Namespaces, ns)
}
