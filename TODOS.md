# TODOS

Items deferred from eng review on 2026-03-18 (branch: master, v0.9.1).

---

### 1. Extract service layer from cli.py

**What:** Move `_build_container_image`, `_build_and_deploy`, `_check_secrets`, `_check_port_availability` into `services.py`. CLI becomes thin command→service dispatch.
**Why:** cli.py is 2,250 lines mixing presentation and business logic. Business logic is untestable in isolation.
**Effort:** human ~2 days / CC ~30 min
**Blocked by:** Nothing. Do when cli.py next needs significant changes.
**Where to start:** Identify all `_` prefixed helper functions in cli.py that don't use Click context. Those are the extraction candidates.

---

### 2. Replace os.system() with subprocess in LimaInstance.start()

**What:** Use `subprocess.Popen` with explicit FD handling instead of `os.system()` for `limactl start`.
**Why:** `os.system()` doesn't capture exit codes reliably and is a shell-injection surface (cage names are trusted today, but defense-in-depth matters for a security tool).
**Effort:** human ~2 hours / CC ~10 min
**Blocked by:** Lima backend stabilization. Need to verify daemonization still works — Lima's hostagent forks background processes that fail when subprocess pipes FDs.
**Where to start:** `src/agentcage/lima/instance.py:start()`. Test with `subprocess.Popen(..., start_new_session=True)` or `close_fds=True`.

---

### 3. Add subnet collision detection

**What:** On `cage create`, check existing deployments' subnets. If `MD5(name) % 254` collides, increment until a free slot is found.
**Why:** Birthday problem — ~50% collision chance at 20 cages. Two cages with the same 10.89.x.0/24 subnet on the same host silently conflict. Flagged as a **critical silent failure mode**.
**Effort:** human ~2 hours / CC ~10 min
**Blocked by:** Nothing.
**Where to start:** `src/agentcage/quadlets.py:cage_network_addrs()`. Add a parameter for existing subnets (from `state.list_deployments()`), loop until no collision.

---

### 4. Unit tests for untested infrastructure modules

**What:** Write tests for 4 modules with zero direct coverage:
- `test_state.py` — save/load round-trips, metadata, list_deployments, corrupted YAML
- `test_har.py` — capture_to_har(), parse_since(), body encoding, edge cases
- `test_container_backend.py` — all Backend protocol methods with mocked subprocess/systemd
- Expand `test_podman.py` — container, image, network, secret operations

**Why:** These modules handle deployment state, forensic export, and the default production backend. Bugs here are silent — state corruption, invalid HAR, broken deploys.
**Effort:** human ~2 days / CC ~1 hour
**Blocked by:** Nothing. All mockable, no external dependencies.
**Where to start:** `state.py` is the highest-value target (pure file I/O, easiest to test with `tmp_path`).

---

### 5. DRY cleanup — shared secret helper + named constants

**What:**
- (a) Extract shared secret prefix-filtering logic from `podman.py` and `lima/podman.py` into a common helper.
- (b) Name magic numbers in `vm.py`: `VM_SERVICE_STARTUP_DELAY_S = 5`, `PROXY_READINESS_TIMEOUT_S = 30`, and in `config.py`: `MAX_CAPTURE_BODY_BYTES = 10_485_760`.

**Why:** Duplicated logic drifts when one copy is updated. Unnamed constants are hard to tune and reason about.
**Effort:** human ~1 hour / CC ~10 min
**Blocked by:** Nothing.
**Where to start:** `src/agentcage/podman.py:secret_list()` vs `src/agentcage/lima/podman.py:secret_list()`.
