# vault-auditor

vault-auditor is a tool to audit a Vault cluster for enabled auth methods, auth
method roles, secrets engines, static secret paths, and policies. To use
vault-auditor, you must have a Vault token with a policy that allows listing and
reading various API paths. The capabilities required for auditing do not include
reading any secret data. See below for the recommended policy definition.

Output is in JSON format. Errors encountered while scanning the Vault cluster
are included in this output.

```text
Usage of vault-auditor:
  -address string
    	Vault cluster API address (default "https://localhost:8200")
  -maxConcurrency int
    	Maximum number of concurrent requests to the Vault API (default 10)
  -rateLimit int
    	Maximum number of requests per second to the Vault API (default 100)
  -tlsSkipVerify
    	Skip TLS verification of the Vault server's certificate
  -token string
    	Vault token with an appropriate audit policy
```

## Recommended Policy
```text
## List Namespaces ##
path "sys/namespaces" {
  capabilities = ["list"]
}

## Read policies ##
path "sys/policy/*" {
  capabilities = ["list", "read"]
}
path "+/sys/policy/*" {
  capabilities = ["list", "read"]
}

## Read secrets engine mounts ##
path "sys/mounts" {
  capabilities = ["read"]
}
path "+/sys/mounts" {
  capabilities = ["read"]
}

## List secrets engine roles ##
path "+/role/*" {
  capabilities = ["list", "read"]
}
path "+/+/role/*" {
  capabilities = ["list", "read"]
}
path "+/roles/*" {
  capabilities = ["list", "read"]
}
path "+/+/roles/*" {
  capabilities = ["list", "read"]
}

## Read auth mounts ##
path "sys/auth" {
  capabilities = ["read"]
}
path "+/sys/auth" {
  capabilities = ["read"]
}

## Read auth roles ##
## (non-namespaced role access is granted by secrets engine policies, which result in the same globbed paths) ##
path "+/auth/+/role/*" {
  capabilities = ["list", "read"]
}
path "+/auth/+/roles/*" {
  capabilities = ["list", "read"]
}

## Read auth certs ##
path "auth/+/certs/*" {
  capabilities = ["list", "read"]
}
path "+/auth/+/certs/*" {
  capabilities = ["list", "read"]
}

## Broad list capability for KV engines ##
path "+/+/metadata/*" {
  capabilities = ["list"]
}
path "+/metadata/*" {
  capabilities = ["list"]
}
path "secret/*" {
  capabilities = ["list"]
}
path "+/secret/*" {
  capabilities = ["list"]
}
path "kv/*" {
  capabilities = ["list"]
}
path "+/kv/*" {
  capabilities = ["list"]
}
# All KV v1 secrets engine paths must have list capability
# For instance, set the last two examples to your KV v1 secrets engine path instead of secret/*
```

## Concurrency and Rate Limiting

This tool can generate excessive load on a Vault cluster. Care should be taken
to evaluate load in a test environment before running in production to ensure
that the load applied is within acceptable tolerances.

The `rateLimit` option is the simplest method to control the generated load, and
is effective as a global limiter regardless of `maxConcurrency`. The default
values should be reasonable under most circumstances, but if there is concern
for cluster stability, limiting the requests per second with `rateLimit` should
provide all of the controls needed.