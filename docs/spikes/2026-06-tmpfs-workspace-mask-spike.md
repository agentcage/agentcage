# Spike: validate tmpfs-masking of `/workspace` persistence surfaces

**Status:** DONE — **CONDITIONAL GO.** Masking prevents cage→host hook persistence on all three backends (A1b PASS everywhere), but it **auto-creates its mountpoint on the host whenever the masked subpath is absent** (A2 FAIL on all backends — and with the RO-bind fallback too). The litter is primitive-independent, so the mask must be applied **only when the host subpath already exists**; the often-absent `.claude` case (#173) needs a different mechanism. Apple-container needs bare `--tmpfs <path>` (no `:opts`) and cannot self-mask from inside the cage. See [Findings & verdict](#findings--verdict-filled-in-2026-06-26).
**Related issues:** [#170](https://github.com/agentcage/agentcage/issues/170) (`.git/hooks` cage→host pivot), [#173](https://github.com/agentcage/agentcage/issues/173) (`.claude/settings.json` cage→cage hooks injection)
**Owner of result:** whoever picks up the #170/#173 fix PR
**Time box:** ~45 minutes

---

## Why this spike exists

The proposed fix for #170 and #173 is to **tmpfs-mask** the dangerous subpaths of the
host-bind workspace mount (`${PROJECT_DIR}:/workspace:rw`) so an in-cage agent can't
plant `.git/hooks/*` or `.claude/settings.json` that persist to the host (or to the next
cage). Before writing that fix we must verify four assumptions the design rests on. If
any fail, the mitigation primitive (tmpfs) is wrong and the plan changes.

**Do not implement the fix until this spike is filled in and the verdict is recorded.**

You are running inside agentcage's defense-in-depth sandbox. There is no direct internet;
that does not affect this spike (it is all local container/VM behavior). Write scratch
files to `/tmp` or the repo worktree, not the read-only root.

---

## Assumptions under test

| # | Assumption | Why it matters | Fail ⇒ |
|---|---|---|---|
| **A1** | A tmpfs mounted at `/workspace/.git/hooks` (a subpath of a host bind mount) **masks** the host's real `.git/hooks` content from inside the cage. | This is the entire mechanism. | tmpfs doesn't mask → pick a different primitive (RO-bind-of-empty-dir). |
| **A2** | When `/workspace/.git/hooks` (or `/workspace/.claude`) **does not exist on the host**, mounting a tmpfs there does **NOT** create a stray `.git/` / `.claude/` directory **on the host**. | Mountpoint auto-creation could litter every non-git / non-claude project with empty `.git/` (which breaks `git`) or `.claude/`. This is the highest-risk unknown. | Host litter occurs → tmpfs is harmful; switch primitive or guard on path existence. |
| **A3** | Mount **ordering** is correct: the parent bind (`/workspace`) is mounted **before** the child tmpfs (`/workspace/.git/hooks`), so the mask actually lands. | Wrong order ⇒ tmpfs is shadowed or errors. | Re-order, or the primitive is unworkable via quadlet. |
| **A4** | Apple's `container run` supports `--tmpfs` (or an equivalent), so the same mask can be enforced on the apple-container backend. | apple-container is a primary backend; its cage VM has only `CAP_NET_ADMIN`, so masking can't be done from inside `cage-init.sh`. | No `--tmpfs` on Apple ⇒ apple-container needs a different fix or a documented gap. |

A1–A3 must be checked on **both** the `container` (podman) backend and, ideally, the `vm`
(Lima/virtiofs) backend, because the workspace mount uses 9p/virtiofs in VM mode and the
behavior can differ. A4 needs a macOS 26 + Apple Silicon host with Apple's `container` CLI.

---

## Environment matrix

Run as many rows as the available hardware allows. Record which rows you ran.

| Backend | Host needed | Tooling |
|---|---|---|
| `container` | Linux (or the dev sandbox) with rootless **podman** | `podman --version` |
| `vm` | macOS or Linux that can run **Lima** | `limactl --version`, `agentcage ... --isolation vm` |
| `apple-container` | **macOS 26+ on Apple Silicon** with Apple `container` CLI | `container --version` |

> If you only have the dev sandbox, you can still do A1–A3 on the `container` backend with
> raw `podman` (Part 1) — that alone de-risks the core mechanism. Mark the other parts
> `NOT RUN (no hardware)`.

---

## Part 1 — `container` backend, raw podman (A1, A2, A3)

This isolates the mount behavior from agentcage entirely. No agentcage build needed.

### 1a. Setup a fake project with a populated `.git/hooks` and NO `.claude`

```bash
set -eux
PROJ=$(mktemp -d /tmp/spike-proj.XXXXXX)
mkdir -p "$PROJ/.git/hooks"
echo '#!/bin/sh'                 > "$PROJ/.git/hooks/pre-commit"
echo 'echo HOST-HOOK-RAN'       >> "$PROJ/.git/hooks/pre-commit"
chmod +x "$PROJ/.git/hooks/pre-commit"
# Deliberately do NOT create $PROJ/.claude — that is the A2 case.
ls -la "$PROJ/.git/hooks"
test ! -e "$PROJ/.claude" && echo "OK: no .claude on host yet"
```

### 1b. Run a container that binds the project and tmpfs-masks both subpaths

```bash
podman run --rm \
  --volume "$PROJ:/workspace:rw" \
  --tmpfs /workspace/.git/hooks:rw,noexec,nosuid,size=8M \
  --tmpfs /workspace/.claude:rw,noexec,nosuid,size=8M \
  alpine:3.20 sh -c '
    echo "--- A1: is host pre-commit visible inside the cage? ---"
    ls -la /workspace/.git/hooks
    if [ -e /workspace/.git/hooks/pre-commit ]; then
      echo "A1 RESULT: FAIL — host hook still visible (mask did not land)"
    else
      echo "A1 RESULT: PASS — host hook masked (dir is empty tmpfs)"
    fi

    echo "--- A1b: can the cage write here, and is it transient? ---"
    echo PWNED > /workspace/.git/hooks/pre-commit
    cat /workspace/.git/hooks/pre-commit

    echo "--- A3: confirm mount order/types from inside ---"
    grep " /workspace" /proc/self/mountinfo || true
    grep " /workspace/.git/hooks" /proc/self/mountinfo || true
    grep " /workspace/.claude" /proc/self/mountinfo || true
  '
```

### 1c. After the container exits, inspect the HOST (A1 persistence + A2 litter)

```bash
echo "--- A1 persistence: did the cage write leak to the host hook? ---"
cat "$PROJ/.git/hooks/pre-commit"
# EXPECT: still the original 'echo HOST-HOOK-RAN' (NOT 'PWNED').
#   If it shows PWNED  -> A1 FAIL (writes leaked to host).

echo "--- A2 litter: did masking .claude create a stray dir on the host? ---"
if [ -e "$PROJ/.claude" ]; then
  echo "A2 RESULT: FAIL — stray $PROJ/.claude created on host:"
  ls -la "$PROJ/.claude"
else
  echo "A2 RESULT: PASS — no stray .claude on host"
fi

echo "--- A2 (git case) sanity: .git/hooks still intact, no weird extra dirs ---"
ls -la "$PROJ/.git/hooks"
```

### 1d. The pure A2 case — tmpfs a path whose parent also doesn't exist

The nastiest variant: project has **no `.git` at all**. Does masking `/workspace/.git/hooks`
create `.git/` on the host?

```bash
PROJ2=$(mktemp -d /tmp/spike-proj2.XXXXXX)   # completely empty, no .git
podman run --rm \
  --volume "$PROJ2:/workspace:rw" \
  --tmpfs /workspace/.git/hooks:rw,noexec,nosuid,size=8M \
  alpine:3.20 sh -c 'ls -la /workspace; ls -la /workspace/.git 2>&1 || true'
echo "--- host check ---"
if [ -e "$PROJ2/.git" ]; then
  echo "A2 RESULT (no-git case): FAIL — stray $PROJ2/.git created on host:"
  find "$PROJ2" -maxdepth 2
else
  echo "A2 RESULT (no-git case): PASS — host project still clean"
fi
```

> If `podman run` **errors** instead of creating the dir (e.g. "no such file or directory"),
> that is itself an important result — record the exact error. It means the mask only works
> when the path pre-exists, which changes the fix (we'd need to guard/conditionalize).

### 1e. Cleanup

```bash
rm -rf "$PROJ" "$PROJ2"
```

---

## Part 2 — `vm` backend (Lima / virtiofs) (A1, A2, A3)

Only if Lima is available. Goal: confirm tmpfs-over-a-**virtiofs** subpath behaves the same
as over a plain bind. Two ways — pick whichever is faster:

**Option A (fastest): real cage.** Build a throwaway ubuntu cage with `--isolation vm`,
add the two tmpfs lines to its `cage.yaml`, point its workspace at the `$PROJ` fixture from
Part 1a, `cage create`, then `cage exec` the same A1/A1b/A3 checks, `cage destroy`, and
re-run the Part 1c/1d host checks.

```bash
# sketch — adapt paths
agentcage init spike-vm --scaffold ubuntu --isolation vm -o /tmp/spike-vm.yaml
# edit /tmp/spike-vm.yaml:
#   - set the workspace volume to "$PROJ:/workspace:rw"
#   - add under container.tmpfs:
#       - "/workspace/.git/hooks:rw,noexec,nosuid,size=8M"
#       - "/workspace/.claude:rw,noexec,nosuid,size=8M"
PROJECT_DIR="$PROJ" agentcage cage create -c /tmp/spike-vm.yaml
agentcage cage exec spike-vm -- sh -c 'ls -la /workspace/.git/hooks; cat /proc/self/mountinfo | grep workspace'
# ...A1/A2/A3 assertions as in Part 1...
agentcage cage destroy spike-vm
```

**Option B (lower-level):** `limactl shell` into a throwaway instance and repeat the raw
`podman run` from Part 1 inside the VM, with the workspace coming from a virtiofs mount.

Record whichever you used.

---

## Part 3 — `apple-container` backend (A4 + A1/A2/A3)

**Requires macOS 26+ on Apple Silicon with Apple's `container` CLI.** If unavailable, mark
this whole part `NOT RUN (no macOS hardware)` — but note that A4 then remains an open risk
that blocks claiming apple-container is protected.

### 3a. Does `container run` even accept `--tmpfs`? (A4)

```bash
container --version
container run --help 2>&1 | grep -iE 'tmpfs|mount|volume' || echo "NO tmpfs/mount flag listed"
```

Then try it for real (this is the authoritative check — `--help` can lag the implementation):

```bash
WORK=$(mktemp -d ~/spike-proj.XXXXXX)   # MUST be under $HOME (apple backend rejects mounts outside $HOME)
mkdir -p "$WORK/.git/hooks"; echo HOST-HOOK > "$WORK/.git/hooks/pre-commit"

container run --rm \
  --volume "$WORK:/workspace" \
  --tmpfs /workspace/.git/hooks:rw,size=8M \
  alpine:3.20 sh -c 'ls -la /workspace/.git/hooks; mount | grep workspace || cat /proc/self/mountinfo | grep workspace'
echo "exit=$?"
```

Record:
- **A4 verdict:** does `--tmpfs` exist / is it accepted / does it error? Paste exact output.
- If accepted: re-run the A1/A2/A3 host-side checks from Part 1c/1d against `$WORK`
  (remember virtiofs identity-maps host ownership into the guest).
- If rejected: note the error. A4 = FAIL ⇒ apple-container cannot use this primitive; the
  fix must either find another mechanism or document apple-container as an unenforced gap.

### 3b. Cleanup

```bash
rm -rf "$WORK"
```

---

## Results — fill this in

Record the agent, date, agentcage version (`echo $AGENTCAGE_VERSION`), and host OS/arch.

```
Run by:        Claude Opus 4.8 (agentcage spike runner)
Date:          2026-06-26
Host:          macOS 26.5.1 (build 25F80), Apple Silicon (arm64, M2 / T8112)
agentcage:     0.25.4  (AGENTCAGE_VERSION unset in env)
podman:        5.6.2  (rootless, inside throwaway Lima `template://podman` VM — Debian/btrfs, kernel 6.12)
limactl:       2.1.1
container CLI:  1.0.0 (build release, commit ee848e3)
docker:        29.5.3 present but daemon not running → not used
```

Methodology note: `container` = real rootless **podman 5.6.2** binding a **plain ext4/btrfs** dir; `vm` = the **same podman** binding a **virtiofs** dir (this is exactly what the agentcage vm backend does — podman inside Lima over virtiofs). Both were run in one throwaway `template://podman` Lima VM. `apple-container` = Apple `container` 1.0.0 directly on the macOS host (its binds are virtiofs).

| Assumption | container (podman, ext4 bind) | vm (podman, virtiofs) | apple-container |
|---|---|---|---|
| **A1** mask works (host content hidden) | **FAIL¹** (copyup) | **FAIL¹** (copyup) | **PASS** (empty tmpfs) |
| **A1b** cage writes are transient (don't leak to host) | **PASS** | **PASS** | **PASS** |
| **A2** no host litter when path absent (`.claude`) | **FAIL** | **FAIL** | **FAIL** |
| **A2** no host litter when `.git` absent | **FAIL** | **FAIL** | **FAIL** |
| **A3** mount order correct (bind before tmpfs) | **PASS** | **PASS** | **PASS** |
| **A4** Apple `container run --tmpfs` supported | n/a | n/a | **YES² (bare path only)** |

¹ **A1 "FAIL" is benign for the #170/#173 threat.** podman performs *tmpcopyup* — it copies the bind's existing `.git/hooks` content into the tmpfs, so an in-cage agent can *read* the host hook. But the security property that actually matters — that in-cage **writes do not persist to the host** — is **A1b, which PASSES on every backend**. apple-container does not copy up (mask is empty). The **RO-bind-of-empty-dir** primitive gives a true empty mask *and* blocks writes (A1 PASS) when the subpath already exists — see supplementary test below.

² Apple's `--tmpfs` takes a **bare path** only. `--tmpfs /p:rw,size=8M` is interpreted as a *literal directory named* `/p:rw,size=8M` (verified: `tmpfs on /mnt/y:rw,size=8M`). The podman/Docker `path:opts` syntax silently masks the wrong directory there → the apple backend must emit bare `--tmpfs /workspace/.git/hooks`.

**Raw output / errors:**

Apple `--tmpfs` format probe (A4 caveat — options string taken literally):
```
# container run --rm --tmpfs /mnt/x         alpine:3  -> mountinfo: "/mnt/x rw,relatime - tmpfs tmpfs rw"   (OK, bare path)
# container run --rm --tmpfs /mnt/y:rw,size=8M alpine:3 -> mount:     "tmpfs on /mnt/y:rw,size=8M type tmpfs" (literal dir name!)
```

apple-container A1/A1b/A3 (mask landed empty, write transient, correct order):
```
--- A1: host pre-commit visible inside the cage? ---  ->  total 0 (empty)  ->  A1 PASS — masked
--- A1b: cage write ---  PWNED   (after exit, host file still: echo HOST-HOOK-RAN)
--- A3 mountinfo ---
 .../...  /workspace            rw,relatime - virtiofs virtiofs rw
 /        /workspace/.git/hooks rw,relatime - tmpfs tmpfs rw
 /        /workspace/.claude    rw,relatime - tmpfs tmpfs rw
--- HOST after exit ---  A2(.claude) FAIL — stray $WORK/.claude created ; A2(nogit) FAIL — stray $WORK2/.git/hooks created
```

podman (container=ext4 and vm=virtiofs), representative ext4 run — note **copyup** + litter:
```
--- A1 ls /workspace/.git/hooks ---  -rwxr-xr-x pre-commit (size 29)  ->  A1 FAIL — host hook visible (tmpcopyup)
--- A3 mountinfo ---
 /var/tmp/spike-proj.XXXX /workspace            rw,relatime - btrfs /dev/vda3 ...
 /                        /workspace/.git/hooks rw,nosuid,nodev,noexec - tmpfs ... size=8192k
 /                        /workspace/.claude    rw,nosuid,nodev,noexec - tmpfs ...
--- HOST after exit ---  pre-commit == "echo HOST-HOOK-RAN" (A1b PASS, PWNED did NOT leak)
                         A2(.claude) FAIL — stray .claude ;  A2(nogit) FAIL — stray .git/hooks
# virtiofs run identical verdicts; /workspace line shows "virtiofs lima-... rw" instead of btrfs.
```

Supplementary — proposed fallback primitive **RO bind-of-empty-dir** (decision-rule A2 option b):
```
CASE A (subpath ABSENT): podman run -v $P:/workspace:rw -v $EMPTY:/workspace/.git/hooks:ro
   inside: write blocked (Read-only file system)   [good]
   HOST:   RO-bind LITTERS — stray $P/.git/hooks created   [BAD — fallback does NOT fix litter]
CASE B (subpath PRESENT): same flags over a real .git/hooks
   inside: /workspace/.git/hooks is EMPTY (true mask, A1 PASS) AND write blocked   [good]
   HOST:   pre-commit intact, no litter   [good — works only because the dir pre-existed]
```

---

## Findings & verdict (filled in 2026-06-26)

**Verdict: CONDITIONAL GO.** The masking *mechanism works for the security goal* but the
naive "always mask the subpath" design is unshippable because it litters clean projects.

1. **The mask stops cage→host persistence on every backend (A1b PASS ×3).** Whether the
   overlay is tmpfs or RO-bind, writes an in-cage agent makes under `/workspace/.git/hooks`
   (or `/workspace/.claude`) land in the ephemeral overlay and are gone when the cage exits.
   The host's real `.git/hooks/pre-commit` was never mutated in any run. This is the core
   defense #170/#173 need, and it holds.

2. **A2 litter is real, universal, and primitive-independent — this is the blocker.**
   Masking a subpath that is **absent on the host** makes the runtime *create the mountpoint*,
   and because the mountpoint lives inside the host bind (`/workspace` == the host dir), the
   `mkdir` is written **through to the host**. Confirmed on podman+ext4, podman+virtiofs, and
   apple-container+virtiofs, and — critically — the **RO-bind-of-empty-dir fallback litters
   too** (supplementary CASE A). So the spike's decision-rule "switch primitive (b)" does
   **not** solve it. `mkdir` is a filesystem op on the shared backing store; no overlay
   primitive and no in-cage mount-namespace trick avoids it (you'd have to mask the *parent*
   first, i.e. hide all of `.git`, which breaks git). **The only litter-free option is to
   mount the mask only when the host subpath already exists.**

3. **Conditional masking is viable for `.git/hooks` but not for `.claude`.**
   - `.git/hooks`: every real git repo already has it, so masking-when-present protects 100%
     of real repos (#170) with zero litter. Residual gap: a non-repo workspace where the
     agent runs `git init` then plants hooks — minor (the agent created that repo itself; no
     pre-existing host repo is pivoted).
   - `.claude` (#173): frequently **absent**, so masking-when-present leaves most projects
     unprotected, and masking-when-absent litters `.claude/` everywhere. This case needs a
     different mechanism — e.g. point Claude's settings/config path away from the workspace
     in the cage so `/workspace/.claude` is never an injection surface, rather than masking it.

4. **Use RO-bind, not tmpfs, where you do mask.** tmpfs on podman *copies up* the existing
   hooks (agent can read them; A1 "FAIL") and *allows* in-cage writes (they're just transient).
   RO-bind-of-empty-dir gives a genuinely empty view **and** hard-blocks writes (CASE B), a
   strictly stronger mask — at the cost of staging an empty host dir to bind. tmpfs needs no
   staging. Either satisfies A1b; choose per whether "hide + block" (RO-bind) or "simplest"
   (tmpfs) is wanted. (apple-container did not copy up, so tmpfs there is already empty.)

5. **apple-container specifics.** (a) `--tmpfs` is accepted (**A4 = YES**) but **bare path
   only** — `:opts` is taken literally, so emit `--tmpfs /workspace/.git/hooks` with no
   options (noexec/nosuid/size cannot ride on this flag; use `--mount type=tmpfs,...` if
   options are required). (b) Apple binds are virtiofs and litter identically. (c) The apple
   cage VM has only `CAP_NET_ADMIN`, so the mask must be applied via the `container run` argv
   from the host launcher — it cannot be done from inside `cage-init.sh`.

### What this means for the #170/#173 fix (re-plan, do not ship the naive version)

- Mask `/workspace/.git/hooks` **only when `${PROJECT_DIR}/.git/hooks` exists on the host**
  (true for all real repos). Prefer **RO-bind of a staged empty dir**; tmpfs is acceptable.
  Wire the same conditional argv into the apple-container backend with a **bare** `--tmpfs`
  (or `--mount type=tmpfs,destination=/workspace/.git/hooks`).
- Do **not** mask `/workspace/.claude` unconditionally — it litters `.claude/` onto clean
  projects on every backend. Solve #173 by relocating the cage's Claude settings/config path
  off the workspace (or document `.claude` as an unenforced gap and gate the claim), rather
  than by masking.
- A3 (ordering) and A4 (apple support) are fine; the gating risk was always A2, and A2 fails
  for the *unconditional* design — hence conditional injection is mandatory.

### How the spike's "Decision rules" resolved

- **A1**: not the real security property; the meaningful one (A1b) passed everywhere. No
  re-plan needed on A1's account, but prefer RO-bind for a true mask.
- **A2 FAIL (the important one)** → decision-rule option **(b) "switch primitive"** is
  **disproven** (RO-bind litters too). Option **(a) "only inject when the subpath exists"**
  is the workable path for `.git/hooks`; `.claude` needs a separate approach (see above).
- **A3 PASS**, **A4 YES** (with the bare-path caveat) → no change required there.

### Environment / cleanup notes

- Tests used a **throwaway** Lima VM (`spike-podman`, `template://podman`) which has been
  **deleted**; all host fixtures (`~/spike-apple*`, `/private/tmp/spike-vfs`) were removed.
  The user's own cages were never used. Observed during the run (NOT caused by this spike —
  every command here only ever named `spike-podman`): the pre-existing Lima instance
  `agentcage-claude-deep-fern` is no longer present and `agentcage-truelayer-pi-vm` went
  Running→Stopped, i.e. concurrent user/agentcage activity.
- Not run: a no-virtiofs pure-Linux host with raw `podman` outside a VM (none available);
  covered equivalently by podman-in-Lima over ext4 for the bind-semantics question.

---

## Decision rules (what each outcome means for the fix)

- **A1 FAIL** anywhere → tmpfs does not mask; switch the primitive to **RO bind-mount of an
  empty host dir** over the subpath (and solve the "empty dir must exist" staging), or the
  detection/sanitize options from #170. Re-plan.
- **A2 FAIL** (host litter) on the `container` backend → tmpfs auto-creates mountpoints on
  the host bind. Either (a) only inject the mask when the subpath already exists (weakens
  the guarantee — a project with no `.git` is unprotected until it gets one), or (b) switch
  primitive. This is the single most important result; do not ship a fix that creates
  `.git/` on users' clean projects.
- **A3 FAIL** → revisit how quadlet emits `Tmpfs=` vs `Volume=` ordering; may need explicit
  ordering or a different rendering.
- **A4 NO** → apple-container can't enforce via `--tmpfs`. Options: document apple-container
  as a known gap for #170/#173 (and gate the claim in the PR), or design an alternative
  (e.g. bake the mask into the wrapper image / cage-init with a mechanism that doesn't need
  `CAP_SYS_ADMIN`).
- **All PASS** → proceed with the tmpfs-mask fix. The container/vm path is solid; wire
  `--tmpfs` into the apple-container backend argv and keep the apple e2e check in the PR.

When done, post the filled-in table to #170 and #173, flip **Status** at the top to
`DONE — <verdict>`, and link this file from the implementing PR.
