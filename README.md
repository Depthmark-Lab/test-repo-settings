# test-repo-settings

Test bed for the `repo-settings` pipeline. Includes a fan-out driver that
creates N repos from a template, opens a PR against `.github/settings/` on
each, and merges the PRs.

## Fan-out driver

Two scripts under `scripts/`:

- `repo-fanout.sh` — orchestrator (`create` / `merge` / `status` / `list`).
- `fanout-change.sh` — per-repo mutator that `multi-gitter` runs inside each
  cloned repo. Randomizes the `description:` line in
  `.github/settings/repo.yml`.

### Prerequisites

- [`gh`](https://cli.github.com/) (authenticated or `GH_TOKEN` exported)
- [`multi-gitter`](https://github.com/lindell/multi-gitter) — install with
  `go install github.com/lindell/multi-gitter@latest` or
  `brew install multi-gitter`
- `jq`

### Required env vars

| Variable        | Purpose                                                               |
| --------------- | --------------------------------------------------------------------- |
| `GH_TOKEN`      | PAT with `repo` + `delete_repo` (and `admin:org` if `TARGET_OWNER` is an org) |
| `TEMPLATE_REPO` | `owner/name` of the template repo (must have `is_template: true`)     |
| `TARGET_OWNER`  | user or org that will own the created repos                           |

### Optional env vars

| Variable      | Default          | Purpose                                       |
| ------------- | ---------------- | --------------------------------------------- |
| `REPO_PREFIX` | `fanout-test`    | name prefix for generated repos               |
| `START_INDEX` | `1`              | starting numeric suffix (`-001`, `-002`, …)   |
| `PRIVATE`     | `true`           | visibility of created repos (`true`/`false`)  |
| `STATE_DIR`   | `.fanout-state`  | where run state files are written             |

### Execution examples

Set the required env once:

```bash
export GH_TOKEN=ghp_xxx
export TEMPLATE_REPO=Depthmark-Lab/test-repo-settings
export TARGET_OWNER=Depthmark-Lab
```

Create 5 repos and open a PR on each:

```bash
scripts/repo-fanout.sh create 5
# => writes .fanout-state/<run-id>.state and prints the run-id
```

Use a custom prefix / start index (e.g., add 3 more without colliding):

```bash
REPO_PREFIX=settings-smoke START_INDEX=6 scripts/repo-fanout.sh create 3
```

List recorded runs, check PR status, then merge:

```bash
scripts/repo-fanout.sh list
scripts/repo-fanout.sh status 20260509T141500Z-12345
scripts/repo-fanout.sh merge  20260509T141500Z-12345
```

Bypass missing/failing required checks (admin only):

```bash
# --admin skips multi-gitter (and its 1s/req self-pacing) and merges every PR
# in parallel via the REST API. Requires the token user to be a repo admin
# and branch protection to allow admin overrides.
scripts/repo-fanout.sh merge 20260509T141500Z-12345 --admin
scripts/repo-fanout.sh merge 20260509T141500Z-12345 --admin --merge-method rebase
scripts/repo-fanout.sh merge 20260509T141500Z-12345 --admin --concurrency 8

# Want parallel direct merges WITHOUT branch-protection bypass?
scripts/repo-fanout.sh merge 20260509T141500Z-12345 --direct --concurrency 6
```

The merge command prints the GitHub rate-limit budget before and after the
run (`core=remaining/limit graphql=remaining/limit reset_in=Ns`), shows live
progress (`done/total ok/fail/ratelimited`), and on failure classifies each
PR's error (`ratelimit`, `secondary`, `checks`, `review`, `conflict`,
`permission`, `notfound`, `other`).

### Cleanup

Delete repos previously created by the fan-out driver. Requires the
`delete_repo` scope on `GH_TOKEN` (plus `admin:org` for org-owned repos).

```bash
# Delete only the repos from one run; removes the state file on success.
scripts/repo-fanout.sh delete <run-id>
scripts/repo-fanout.sh delete --run <run-id> --yes

# Delete every repo under $TARGET_OWNER whose name starts with $REPO_PREFIX-.
scripts/repo-fanout.sh delete --all --dry-run         # preview
scripts/repo-fanout.sh delete --all --yes --concurrency 8
```

Without `--yes` the command prints the list and asks you to type `DELETE N`
(where N is the count) before anything is removed.

Re-running `create` with the same `REPO_PREFIX` reuses existing repos and just
opens a new branch + PR on each (no recreation).
