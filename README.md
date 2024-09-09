# vault-auditor

vault-auditor is a tool to audit a Vault cluster for enabled auth methods, auth
method roles, secrets engines, static secret paths, and policies. To use
vault-auditor, you must have a Vault token with a policy that allows listing all
API paths. If the policy additionally permits reading policies, referenced paths
will be included in the output.

Output is in JSON format. Errors encountered while scanning the Vault cluster
are included in this output.

```shell
Usage of vault-auditor:
  -address string
        Vault cluster API address (default "https://localhost:8200")
  -tlsSkipVerify
        Skip TLS verification of the Vault server's certificate
  -token string
        Vault token with a policy that allows listing all API paths
```