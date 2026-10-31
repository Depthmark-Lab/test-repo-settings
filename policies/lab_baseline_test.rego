# Conformance tests for lab_baseline.rego and lab_data.json, the policy bundle
# for this repository's harness Apps. Mirrors the structure of
# Depthmark-Lab/test-github-sts's policies/lab_baseline_test.rego. Run with:
#   opa test policies
package sts.enterprise.v1_test

import data.sts.enterprise.v1 as baseline

issuer := "https://token.actions.githubusercontent.com"

harness_repo := "Depthmark-Lab/test-repo-settings"

# An exchange from and to test-repo-settings, shaped like the broker's input.
settings_input(app, identity, permissions) := {
	"mode": "exchange",
	"request": {"scope": harness_repo, "app": app, "identity": identity},
	"source_identity": {
		"version": "v1",
		"issuer": issuer,
		"repository_owner": "Depthmark-Lab",
		"repository_owner_id": "71595780",
		"repository": harness_repo,
		"repository_id": "1218555600",
	},
	"target_identity": {
		"version": "v1",
		"scope": harness_repo,
		"repository_owner": "Depthmark-Lab",
		"repository_owner_id": "71595780",
		"repository": harness_repo,
		"repository_id": "1218555600",
	},
	"yaml_policy": {"github": {
		"sources": [{"owner_id": "71595780", "repository_id": "1218555600"}],
		"target": {"owner_id": "71595780", "repository_id": "1218555600"},
	}},
	"requested": {
		"permissions": permissions,
		"organization_wide": false,
		"repository_ids": ["1218555600"],
	},
	"authorization": {"cross_org_exceptions": []},
}

verify_profile := {
	"metadata": "read",
	"contents": "read",
	"administration": "read",
	"actions": "read",
	"secrets": "read",
	"repository_hooks": "read",
	"pages": "read",
}

preflight_profile := {
	"metadata": "read",
	"organization_administration": "read",
	"organization_custom_properties": "read",
}

# ─── Broker admission ────────────────────────────────────────────────────────
# github-sts loads a required bundle only when its declared admission context
# is allowed and four generated probes are denied. probe_input mirrors
# mandatoryProbeInput in github-sts's internal/bundle/engine.go.

admission := baseline.metadata.admission

probe_scope := "github-sts-admission/target"

probe_input(permissions) := {
	"mode": "exchange",
	"request": {"scope": probe_scope, "app": admission.app, "identity": admission.identity},
	"yaml_policy": {
		"issuer": issuer,
		"permissions": admission.permissions,
		"github": {"sources": [admission.source], "target": admission.target},
	},
	"claims": {"iss": issuer},
	"source_identity": {
		"version": "v1",
		"issuer": issuer,
		"repository_owner": "github-sts-admission",
		"repository_owner_id": admission.source.owner_id,
		"repository": "github-sts-admission/source",
		"repository_id": admission.source.repository_id,
		"immutable_subject": true,
		"immutable_subject_required": true,
	},
	"target_identity": {
		"version": "v1",
		"scope": probe_scope,
		"repository_owner": "github-sts-admission",
		"repository_owner_id": admission.target.owner_id,
		"repository": probe_scope,
		"repository_id": admission.target.repository_id,
	},
	"requested": {
		"permissions": permissions,
		"repositories": [probe_scope],
		"repository_ids": [admission.target.repository_id],
		"organization_wide": false,
	},
	"authorization": {"cross_org_exceptions": []},
}

test_metadata_contract if {
	baseline.metadata.contract_version == "v1"
	baseline.metadata.policy_revision == "1"
	baseline.metadata.controls[_] == "immutable_identity"
	baseline.metadata.controls[_] == "permission_boundary"
}

test_admission_context_allows if {
	decision := baseline.decision with input as probe_input(admission.permissions)
	decision.allow
}

test_probe_malformed_input_denied if {
	decision := baseline.decision with input as object.union(probe_input(admission.permissions), {"mode": "invalid"})
	not decision.allow
}

test_probe_missing_identity_denied if {
	decision := baseline.decision with input as object.remove(probe_input(admission.permissions), ["source_identity"])
	not decision.allow
}

test_probe_unknown_source_denied if {
	unknown := {"owner_id": "99999999999999999999999999999999999998", "repository_id": "99999999999999999999999999999999999999"}
	probe := object.union(probe_input(admission.permissions), {
		"source_identity": {"repository_owner_id": unknown.owner_id, "repository_id": unknown.repository_id},
		"yaml_policy": {"github": {"sources": [unknown]}},
	})
	decision := baseline.decision with input as probe
	not decision.allow
}

test_probe_unknown_permission_denied if {
	decision := baseline.decision with input as probe_input({"github_sts_unknown_permission": "write"})
	not decision.allow
}

# ─── Harness identities ──────────────────────────────────────────────────────

test_allow_verify_full_read_profile if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-verify", verify_profile)
	decision.allow
	decision.rule_id == "sts.enterprise.allow"
}

test_deny_verify_write_request if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-verify", {"administration": "write"})
	not decision.allow
	decision.rule_id == "sts.permissions.exceeds_ceiling"
}

# Organization-level reads belong to the preflight identity only.
test_deny_verify_organization_read if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-verify", {"organization_administration": "read"})
	not decision.allow
	decision.rule_id == "sts.permissions.exceeds_ceiling"
}

# github-sts can't mint actions_variables yet, so no ceiling includes it.
test_deny_verify_actions_variables if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-verify", {"actions_variables": "read"})
	not decision.allow
	decision.rule_id == "sts.permissions.exceeds_ceiling"
}

test_allow_preflight_organization_reads if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-preflight", preflight_profile)
	decision.allow
	decision.rule_id == "sts.enterprise.allow"
}

test_deny_preflight_repository_read if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "repo-settings-preflight", {"administration": "read"})
	not decision.allow
	decision.rule_id == "sts.permissions.exceeds_ceiling"
}

# test-github-sts's dual AKV check: that repository as source and target, whose
# trust policy lives there, and metadata only.
dual_akv_input(identity, permissions) := object.union(settings_input("test-settings-read-app", identity, permissions), {
	"request": {"scope": "Depthmark-Lab/test-github-sts"},
	"source_identity": {"repository": "Depthmark-Lab/test-github-sts", "repository_id": "1223040727"},
	"target_identity": {"scope": "Depthmark-Lab/test-github-sts", "repository": "Depthmark-Lab/test-github-sts", "repository_id": "1223040727"},
	"yaml_policy": {"github": {
		"sources": [{"owner_id": "71595780", "repository_id": "1223040727"}],
		"target": {"owner_id": "71595780", "repository_id": "1223040727"},
	}},
	"requested": {"repository_ids": ["1223040727"]},
})

test_allow_dual_akv_check_metadata if {
	decision := baseline.decision with input as dual_akv_input("dual-akv-check", {"metadata": "read"})
	decision.allow
	decision.rule_id == "sts.enterprise.allow"
}

test_deny_dual_akv_check_above_metadata if {
	decision := baseline.decision with input as dual_akv_input("dual-akv-check", {"contents": "read"})
	not decision.allow
	decision.rule_id == "sts.permissions.exceeds_ceiling"
}

# A source the trust policy does not list is refused, whatever the bundle allows.
test_deny_dual_akv_check_unlisted_source if {
	unlisted := object.union(dual_akv_input("dual-akv-check", {"metadata": "read"}), {
		"source_identity": {"repository": "Depthmark-Lab/other", "repository_id": "1"},
	})
	decision := baseline.decision with input as unlisted
	not decision.allow
	decision.rule_id == "sts.relationship.source_target"
}

# The harness identities stay on test-repo-settings.
test_deny_verify_on_test_github_sts if {
	decision := baseline.decision with input as dual_akv_input("repo-settings-verify", {"metadata": "read"})
	not decision.allow
	decision.rule_id == "sts.context.unknown"
}

# dual-akv-check stays on test-github-sts.
test_deny_dual_akv_check_on_test_repo_settings if {
	decision := baseline.decision with input as settings_input("test-settings-read-app", "dual-akv-check", {"metadata": "read"})
	not decision.allow
	decision.rule_id == "sts.context.unknown"
}

# The read pool reaches only the targets lab_data.json names.
test_deny_read_pool_unlisted_target if {
	other := "Depthmark-Lab/other"
	unlisted := object.union(settings_input("test-settings-read-app", "repo-settings-verify", {"metadata": "read"}), {
		"request": {"scope": other},
		"target_identity": {"scope": other, "repository": other, "repository_id": "1"},
		"yaml_policy": {"github": {"target": {"owner_id": "71595780", "repository_id": "1"}}},
		"requested": {"repository_ids": ["1"]},
	})
	decision := baseline.decision with input as unlisted
	not decision.allow
	decision.rule_id == "sts.context.unknown"
}

# The write pool has no targets until the sandbox repositories exist.
test_deny_write_pool_without_targets if {
	decision := baseline.decision with input as settings_input("test-settings-write-app", "sandbox-reset", {"contents": "write"})
	not decision.allow
	decision.rule_id == "sts.context.unknown"
}

test_deny_app_outside_this_bundle if {
	decision := baseline.decision with input as settings_input("test-checkout-app", "ci", {"contents": "read"})
	not decision.allow
	decision.rule_id == "sts.context.unknown"
}
