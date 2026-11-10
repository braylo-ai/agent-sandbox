// Agent sandbox authorization policy (Cedar syntax, evaluated by sandbox/cedar.py).
// Default deny. Any matching forbid overrides every permit.

// Files: read or write only inside the workspace of the task the credential is bound to.
permit (principal in Role::"agent", action == Action::"file_read", resource is File)
when { resource.task == context.task && context.scopes.contains("fs:read") };

permit (principal in Role::"agent", action == Action::"file_write", resource is File)
when { resource.task == context.task && context.scopes.contains("fs:write") };

// Network: needs the egress scope; the proxy enforces the host allowlist.
permit (principal in Role::"agent", action in [Action::"http_get", Action::"http_post"], resource is Host)
when { context.scopes.contains("net:egress") };

// Secrets: only the task's own secrets, only with the secret scope.
permit (principal in Role::"agent", action == Action::"secret_read", resource is Secret)
when { resource.task == context.task && context.scopes.contains("secret:read") };

// Spawning a sub-agent: needs the scope, and the child may not get broader scopes.
permit (principal in Role::"agent", action == Action::"spawn_agent", resource is Agent)
when { context.scopes.contains("agent:spawn") && context.child_scopes_subset == true };

// Agents can never change policy, credentials or the audit log.
forbid (principal in Role::"agent", action in [Action::"policy_update", Action::"credential_issue"], resource);

forbid (principal, action in [Action::"file_write", Action::"file_delete"], resource is File)
when { resource.path like "*/.audit*" };

// Uploads (POST) to hosts tagged paste/file-share are forbidden even if allowlisted.
forbid (principal, action == Action::"http_post", resource is Host)
when { resource has category && resource.category == "file_share" };
