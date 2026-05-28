<!-- owner: @luca  last-reviewed: 2026-05-28 -->
# Deploy to a server

How to run agentcage unattended on a Linux server under a dedicated service user. Read this when promoting a cage from your laptop to a long-running host.

## What you'll set up

Each cage runs as its own unprivileged Linux user (e.g. `myapp-svc`). The user owns its podman storage, its quadlet files under `~/.config/containers/systemd/`, and its rootless systemd user session. Lingering keeps the session alive while no one is logged in, so the cage's quadlets stay up across reboots. `lifecycle: service` (the default in `cage.yaml`) wires `Restart=on-failure` into the generated quadlets, so transient failures recover without intervention.

One service user per cage gives you process, filesystem, and audit isolation between unrelated workloads on the same host. Two cages that talk to different upstreams should not share a UID.

## Create the service user

Pick a short name. Create the account, give it a real home directory, and seed lingering so its systemd user manager comes up at boot:

```bash
sudo useradd --create-home --shell /bin/bash myapp-svc
sudo touch /var/lib/systemd/linger/myapp-svc
```

> Why `touch` instead of `loginctl enable-linger`? Inside cloud-init (or any boot-time provisioning that runs `usermod -aG` against the same user immediately before), `loginctl enable-linger` can deadlock waiting for a dbus round-trip. Writing the marker file directly is what `loginctl` does internally, and `systemd-logind` picks it up via inotify with no dbus required.

Confirm the runtime directory comes up:

```bash
sudo -u myapp-svc bash -c 'ls /run/user/$(id -u)'
```

You should see entries like `systemd/` and `bus`. If `/run/user/<uid>` is empty, lingering did not take effect — reboot or run `sudo systemctl restart systemd-logind`.

## Install agentcage as that user

The standard installer works fine under the service user, but you need a TTY-less invocation. Run it from your shell with `sudo -u`:

```bash
sudo -u myapp-svc bash -c '
  cd ~ &&
  export PATH="$HOME/.local/bin:$PATH" XDG_RUNTIME_DIR=/run/user/$(id -u) &&
  curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh
'
```

Two environment variables matter:

- **`PATH`** must include `~/.local/bin` so `uv` and `agentcage` are found.
- **`XDG_RUNTIME_DIR`** must point at the user's `/run/user/<uid>`. Without it, rootless podman and `systemctl --user` cannot find the user's dbus socket and fail with cryptic permission errors.

You also need to `cd ~` before running anything as the service user — your interactive shell's working directory is usually unreadable by `myapp-svc`, and uv refuses to start there.

If you prefer to skip the installer and you already have podman, Python 3.12+, and uv on the host:

```bash
sudo -u myapp-svc bash -c '
  cd ~ &&
  export PATH="$HOME/.local/bin:$PATH" XDG_RUNTIME_DIR=/run/user/$(id -u) &&
  uv tool install agentcage
'
```

Verify the install:

```bash
sudo -u myapp-svc bash -c '
  cd ~ &&
  export PATH="$HOME/.local/bin:$PATH" XDG_RUNTIME_DIR=/run/user/$(id -u) &&
  agentcage doctor
'
```

`agentcage doctor` checks podman, uv, Python, and (on Linux) the rootless network setup. Fix any reported issues before continuing.

## Run as that user

The `sudo -u … bash -c '…'` pattern is verbose. Drop a helper into your own shell's rc so you can run any agentcage command as the service user:

```bash
# In ~/.bashrc on the host
asuser() {
  local user="$1"; shift
  sudo -u "$user" bash -c "
    cd ~ &&
    export PATH=\"\$HOME/.local/bin:\$PATH\" XDG_RUNTIME_DIR=/run/user/\$(id -u) &&
    $*
  "
}
```

Then everything reads naturally:

```bash
asuser myapp-svc agentcage cage list
asuser myapp-svc agentcage cage audit myapp --since 10m
```

## Create and start the cage

Author `cage.yaml` as the service user so paths under `volumes:` resolve in its home directory:

```bash
asuser myapp-svc agentcage init myapp --scaffold openclaw
```

The scaffold drops a config at `~/.config/agentcage/cages/myapp/cage.yaml`. Confirm it has `lifecycle: service` (the default) — anything else won't auto-restart on failure.

Set the secrets the cage needs. The `secret set` command stores them in podman secrets (or systemd-creds if available):

```bash
asuser myapp-svc agentcage secret set myapp ANTHROPIC_API_KEY
```

You'll be prompted for the value. Repeat for any other secrets your `secret_injection:` rules reference.

Build and start:

```bash
asuser myapp-svc agentcage cage create myapp
```

This generates quadlet files into `~/.config/containers/systemd/`, runs `systemctl --user daemon-reload`, and starts the cage's units. Because `lifecycle: service`, the quadlets carry `Restart=on-failure` and survive transient crashes.

Verify everything is running:

```bash
asuser myapp-svc agentcage cage list
asuser myapp-svc agentcage cage logs myapp -s proxy --tail 20
```

The proxy log should show the inspector chain loading and mitmproxy listening on the internal network.

## Reach the cage

If the cage publishes an HTTP service, declare the inbound forward in `cage.yaml`:

```yaml
container:
  ports:
    - "8080:8080"  # host:container
```

agentcage serves published ports through mitmproxy in reverse mode, so inbound HTTP traffic goes through the full inspector chain. After editing `cage.yaml`:

```bash
asuser myapp-svc agentcage cage update myapp
```

Three common ways to expose the published port to the outside world:

- **Reverse proxy on the host.** Point Caddy or nginx at `127.0.0.1:8080`. Terminate TLS at the reverse proxy; the cage's mitmproxy speaks plain HTTP on the published listener.
- **Tailscale.** Install Tailscale on the host, run `tailscale serve 8080`, and reach the cage by Tailscale hostname over WireGuard. No public port required.
- **Direct.** Open the firewall on the relevant port if the host is meant to be public. The proxy's domain allowlist and inspector chain still apply.

Do not give the service user sudo to manage firewall rules — that defeats the isolation. The host operator owns inbound networking; the cage owns its own egress.

## Day 2 operations

- **Backups, restore, and disaster recovery** live in [back up and restore](back-up-and-restore.md).
- **When something is broken,** start at [troubleshoot](troubleshoot.md). The most common server-side failure is a stale `XDG_RUNTIME_DIR` (the user logged out and the runtime dir was cleaned up) — the fix is in there.
- **Upgrading agentcage itself** is covered in [upgrade agentcage](upgrade-agentcage.md), including the linger-and-restart dance you need when bumping past a major version.

## Multi-cage on the same host

Run a second cage under a second service user — never under the same UID:

```bash
sudo useradd --create-home --shell /bin/bash other-svc
sudo touch /var/lib/systemd/linger/other-svc
asuser other-svc 'curl -fsSL https://raw.githubusercontent.com/agentcage/agentcage/master/install.sh | sh'
asuser other-svc agentcage init other --scaffold codex
asuser other-svc agentcage cage create other
```

Why separate users: every defense layer agentcage offers — capture files, audit logs, podman secrets, named volumes, the inspector path allowlist — is enforced inside one user's filesystem and one user's rootless podman instance. Two cages under one UID share all of those. Two cages under two UIDs share none of them. The cost is one extra `useradd` and one extra `touch` per cage.

Pair this with port-policy hygiene: each cage's `ports.tcp.allow` lists only the upstream ports it actually needs. The default-deny FORWARD chain drops everything else, so a second cage on the same host cannot accidentally proxy traffic for the first.

## Related

- [Troubleshoot](troubleshoot.md) — diagnostic recipes for stuck cages
- [CLI reference](../reference/cli.md) — full command set
- [Back up and restore](back-up-and-restore.md) — snapshotting state and secrets
- [Upgrade agentcage](upgrade-agentcage.md) — version bumps under a service user
- [Port policy](../reference/ports.md) — inbound forwards and the FORWARD chain
