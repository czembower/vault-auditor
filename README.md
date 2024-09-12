# vault-auditor

`vault-auditor` is a tool to scan a Vault cluster for enabled auth methods, auth
method roles, secrets engines, static secret paths, entities, and policies. To
use `vault-auditor`, you must have a Vault token with a policy that allows
listing and reading various API paths. The capabilities required for auditing do
not include reading any secret data. See below for the recommended policy
definition.

Output is in JSON format. Errors encountered while scanning the Vault cluster
are included in this output. If your anticipate a large output, it is
recommended to redirect the output to a file:

```shell
vault-auditor -token $AUDIT_TOKEN > vault-audit.json
```

## Usage
```text
Usage of vault-auditor:
  -address string
    	Vault cluster API address (default "https://localhost:8200")
  -listSecrets
    	List all KV engine secrets in the cluster (WARNING: this may produce a large amount of data)
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
The below policy example will enable `vault-auditor` to perform all available
scanning, parsing, and reporting functions. If a policy does not permit access
to a desired path, the auditor will still run and perform other tasks, but will
log an error in the output. Any reported errors should aid you in adjusting the
policy for `vault-auditor` to your satisfaction.

Note that KV v1 engines must be added to this policy if using a path other than
`kv` or `secret`.

```text
## List Namespaces ##
path "sys/namespaces" {
  capabilities = ["list"]
}

## Read counters ##
path "sys/internal/counters/activity/monthly" {
  capabilities = ["read"]
}

## Read policies ##
path "sys/policy/*" {
  capabilities = ["list", "read"]
}
path "+/sys/policy/*" {
  capabilities = ["list", "read"]
}

## Read entities ##
path "identity/entity/id/*" {
  capabilities = ["list", "read"]
}
path "+/identity/entity/id/*" {
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