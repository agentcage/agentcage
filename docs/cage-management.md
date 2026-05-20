# Managing Your Cage

Common commands for managing an agentcage cage. Replace `myapp` with your cage name.

## Day-to-day operations

```bash
# Edit config directly, then apply (rebuilds + reloads)
$EDITOR ~/.config/agentcage/cages/myapp/cage.yaml && agentcage cage update myapp

# Rebuild and restart (after config or image changes)
agentcage cage update myapp

# Restart without rebuilding
agentcage cage restart myapp

# View proxy audit logs
agentcage cage audit myapp

# Destroy (stops containers, removes quadlets and state)
agentcage cage destroy myapp
```

## Troubleshooting

**403 errors from the proxy**: Check proxy logs: `agentcage cage logs myapp -s proxy`. The JSON entries include a `reason` field explaining the block. Either the domain is not in your allowlist, or a secret pattern was detected.

**Certificate errors**: The mitmproxy CA cert is shared via a named volume. If TLS errors occur, restart the cage: `agentcage cage restart myapp`.

**DNS resolution failures**: Verify the DNS sidecar is running: `agentcage cage list`. If using custom `dns_servers`, ensure they are reachable from the host.

**File permission errors in /workspace**: The scaffold uses `userns: "keep-id"` to map your host UID into the container. Check that mounted directories are owned by your user on the host.
