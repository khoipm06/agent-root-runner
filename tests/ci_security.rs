use std::collections::BTreeSet;

const WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
const AI_REVIEW_SOURCE: &str = include_str!("../.github/workflows/ai-pr-review.md");
const AI_REVIEW_LOCK: &str = include_str!("../.github/workflows/ai-pr-review.lock.yml");
const ISSUE_TRIAGE_SOURCE: &str = include_str!("../.github/workflows/ai-issue-triage.md");
const ISSUE_TRIAGE_LOCK: &str = include_str!("../.github/workflows/ai-issue-triage.lock.yml");
const COPILOT_GUIDANCE: &str = include_str!("../.github/copilot-instructions.md");
const NATIVE_RUNTIME_TESTS: &str = include_str!("native_runtime.rs");

fn job_block(document: &str, name: &str) -> String {
    let marker = format!("  {name}:\n");
    let start = document
        .find(&marker)
        .unwrap_or_else(|| panic!("missing workflow job {name}"))
        + marker.len();
    let mut block = String::new();
    for line in document[start..].lines() {
        if line.starts_with("  ") && !line.starts_with("    ") && !line.trim().is_empty() {
            break;
        }
        block.push_str(line);
        block.push('\n');
    }
    block
}

fn workflow_yaml(document: &str) -> serde_yaml::Value {
    serde_yaml::from_str(document).expect("workflow YAML must parse")
}

fn job_names(document: &str) -> Vec<String> {
    let root = workflow_yaml(document);
    let jobs = root
        .get("jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("workflow jobs section must be a mapping");
    let mut names = jobs
        .keys()
        .map(|key| key.as_str().unwrap_or("<non-string-job-key>").to_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn permission_write_grants(
    name: &str,
    permissions: Option<&serde_yaml::Value>,
) -> BTreeSet<String> {
    let mut grants = BTreeSet::new();
    let Some(permissions) = permissions else {
        return grants;
    };
    if let Some(value) = permissions.as_str() {
        match value {
            "read-all" => return grants,
            "write-all" => {
                grants.insert(format!("{name}:*"));
            }
            _ => {
                grants.insert(format!("{name}:<unparsed-permissions-value>"));
            }
        }
        return grants;
    }
    let Some(scopes) = permissions.as_mapping() else {
        grants.insert(format!("{name}:<unparsed-permissions-value>"));
        return grants;
    };
    for (scope, value) in scopes {
        let Some(scope) = scope.as_str() else {
            grants.insert(format!("{name}:<unparsed-permission-scope>"));
            continue;
        };
        if scope == "<<" {
            grants.insert(format!("{name}:<yaml-merge-key>"));
            continue;
        }
        match value.as_str() {
            Some("read" | "none") => (),
            Some("write") => {
                grants.insert(format!("{name}:{scope}"));
            }
            _ => {
                grants.insert(format!("{name}:<unparsed-permission-value>"));
            }
        }
    }
    grants
}

fn job_write_permissions(document: &str, name: &str) -> BTreeSet<String> {
    let root = workflow_yaml(document);
    let Some(jobs) = root.get("jobs").and_then(serde_yaml::Value::as_mapping) else {
        return BTreeSet::from([format!("{name}:<missing-jobs-mapping>")]);
    };
    let key = serde_yaml::Value::String(name.to_owned());
    let Some(job) = jobs.get(&key) else {
        return BTreeSet::from([format!("{name}:<missing-job>")]);
    };
    let Some(job) = job.as_mapping() else {
        return BTreeSet::from([format!("{name}:<unparsed-job>")]);
    };
    let permissions_key = serde_yaml::Value::String("permissions".to_owned());
    permission_write_grants(
        name,
        job.get(&permissions_key)
            .or_else(|| root.get("permissions")),
    )
}

fn frontmatter(document: &str) -> &str {
    document
        .strip_prefix("---\n")
        .and_then(|document| document.split_once("\n---\n"))
        .map(|(metadata, _)| metadata)
        .expect("workflow frontmatter is missing")
}

fn lock_json_env(key: &str) -> serde_json::Value {
    let prefix = format!("{key}: ");
    let raw = AI_REVIEW_LOCK
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing generated setting {key}"));
    let decoded: String = serde_json::from_str(raw)
        .unwrap_or_else(|error| panic!("invalid encoded JSON in {key}: {error}"));
    serde_json::from_str(&decoded)
        .unwrap_or_else(|error| panic!("invalid JSON payload in {key}: {error}"))
}

fn lock_multiline_json_env(key: &str) -> serde_json::Value {
    let marker = format!("          {key}: |\n");
    let start = AI_REVIEW_LOCK
        .find(&marker)
        .unwrap_or_else(|| panic!("missing generated multiline setting {key}"))
        + marker.len();
    let mut json = String::new();
    for line in AI_REVIEW_LOCK[start..].lines() {
        let Some(content) = line.strip_prefix("            ") else {
            break;
        };
        json.push_str(content);
        json.push('\n');
    }
    serde_json::from_str(&json)
        .unwrap_or_else(|error| panic!("invalid multiline JSON in {key}: {error}"))
}

#[test]
fn write_token_is_confined_to_the_non_code_release_publisher() {
    let (workflow_header, _) = WORKFLOW
        .split_once("\njobs:\n")
        .expect("CI workflow jobs section is missing");
    let default_permissions = workflow_header
        .split_once("\npermissions:\n")
        .expect("CI workflow default permissions are missing")
        .1
        .lines()
        .take_while(|line| line.starts_with("  "))
        .collect::<Vec<_>>();
    assert_eq!(default_permissions, ["  contents: read"]);

    let actual_write_permissions = job_names(WORKFLOW)
        .into_iter()
        .flat_map(|name| job_write_permissions(WORKFLOW, &name))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_write_permissions,
        BTreeSet::from(["publish-release:contents".to_owned()])
    );

    let publisher = job_block(WORKFLOW, "publish-release");
    assert!(publisher.contains("contents: write"));
    assert!(publisher.contains("softprops/action-gh-release"));
    assert!(!publisher.contains("actions/checkout"));
    assert!(
        publisher.contains(
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0"
        )
    );
    assert!(
        publisher.contains(
            "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2.6.2"
        )
    );
    assert!(
        !publisher
            .lines()
            .any(|line| line.trim_start().starts_with("run:"))
    );
}

#[test]
fn permission_scanner_detects_inline_and_write_all_grants() {
    let inline = "jobs:\n  agent:\n    permissions: { contents: read, pull-requests: read, actions: write }\n";
    assert_eq!(
        job_write_permissions(inline, "agent"),
        BTreeSet::from(["agent:actions".to_owned()])
    );

    let multiline_inline =
        "jobs:\n  agent:\n    permissions: {\n      'issues': read,\n      actions: write\n    }\n";
    assert_eq!(
        job_write_permissions(multiline_inline, "agent"),
        BTreeSet::from(["agent:actions".to_owned()])
    );

    assert_eq!(
        job_write_permissions("jobs:\n  agent:\n    permissions: write-all\n", "agent"),
        BTreeSet::from(["agent:*".to_owned()])
    );

    let anchored_map = "jobs:\n  agent:\n    permissions: &review-permissions\n      contents: read\n      actions: write\n  alias:\n    permissions: *review-permissions\n";
    assert!(job_write_permissions(anchored_map, "agent").contains("agent:actions"));
    assert!(job_write_permissions(anchored_map, "alias").contains("alias:actions"));

    let merged_map = "jobs:\n  agent:\n    permissions: &review-permissions\n      actions: write\n  alias:\n    permissions:\n      <<: *review-permissions\n";
    let merged_grants = job_write_permissions(merged_map, "alias");
    assert!(
        merged_grants.contains("alias:actions") || merged_grants.contains("alias:<yaml-merge-key>")
    );

    let folded_value = "jobs:\n  agent:\n    permissions:\n      actions: >-\n        write\n";
    assert!(job_write_permissions(folded_value, "agent").contains("agent:actions"));

    let tagged_map = "jobs:\n  agent:\n    permissions: !!map\n      actions: write\n";
    assert!(job_write_permissions(tagged_map, "agent").contains("agent:actions"));

    let escaped_key = "jobs:\n  agent:\n    \"\\u0070ermissions\": { actions: write }\n";
    assert_eq!(
        job_write_permissions(escaped_key, "agent"),
        BTreeSet::from(["agent:actions".to_owned()])
    );

    let commented_flow_map = "jobs:\n  agent:\n    permissions: {\n      contents: read, # describe the read grant\n      actions: write\n    }\n";
    assert!(job_write_permissions(commented_flow_map, "agent").contains("agent:actions"));

    let flow_job = "jobs:\n  injected: { runs-on: ubuntu-latest, permissions: write-all, steps: [{ run: \"echo ok\" }] }\n";
    assert_eq!(job_names(flow_job), ["injected"]);
    assert!(job_write_permissions(flow_job, "injected").contains("injected:*"));
}

#[test]
fn candidate_code_jobs_are_read_only_and_native_only() {
    for name in ["test", "build-release"] {
        let block = job_block(WORKFLOW, name);
        assert!(
            block.contains("contents: read"),
            "{name} lacks read permission"
        );
        assert!(
            block.contains("persist-credentials: false"),
            "{name} persists checkout credentials"
        );
        assert_eq!(
            job_write_permissions(WORKFLOW, name),
            BTreeSet::new(),
            "{name} has a write permission or an unparsed permission form"
        );
        assert!(
            !block.contains("setup-python"),
            "{name} installs Python tooling"
        );
        assert!(!block.contains("python -m"), "{name} invokes Python tests");
    }
    assert!(WORKFLOW.contains("cargo test --locked --all-targets"));
    assert!(WORKFLOW.contains("cargo test --locked --release --test release_runtime"));
}

#[test]
fn protected_path_payload_tests_require_explicit_authorization() {
    let ignore = "#[test]\n#[ignore = \"submits protected-path payloads; requires explicit authorization\"]\n";
    for name in [
        "native_socket_state_quota_guardrail_audit_and_modes",
        "real_daemon_blocks_m4_and_wrapper_evasion_probes",
        "daemon_guardrails_use_the_actual_workdir_and_follow_its_symlinks",
    ] {
        assert!(
            NATIVE_RUNTIME_TESTS.contains(&format!("{ignore}fn {name}()")),
            "protected-path test {name} must remain ignored by default"
        );
    }
}

#[test]
fn ai_pr_review_is_advisory_and_generated_permissions_are_scoped() {
    let source = frontmatter(AI_REVIEW_SOURCE);
    assert!(source.contains("permissions:\n  contents: read\n  pull-requests: read"));
    assert!(!source.contains("write"));
    assert!(AI_REVIEW_SOURCE.contains("Submit one `COMMENT` review"));
    assert!(AI_REVIEW_SOURCE.contains("never approve, request changes, merge"));
    assert!(COPILOT_GUIDANCE.contains(
        "activation job's `issues: write` permission is solely for the framework's blocked-version notice"
    ));

    let safe_outputs = source
        .split_once("safe-outputs:\n")
        .map(|(_, rest)| rest.split_once("\nmax-turns:").unwrap().0)
        .expect("safe outputs are missing");
    assert!(safe_outputs.contains("allowed-events: [COMMENT]"));
    let configured_outputs = safe_outputs
        .lines()
        .filter(|line| line.starts_with("  ") && !line.starts_with("    "))
        .map(|line| line.trim().trim_end_matches(':'))
        .collect::<Vec<_>>();
    assert_eq!(
        configured_outputs,
        [
            "create-pull-request-review-comment",
            "submit-pull-request-review"
        ]
    );

    let (workflow_header, _) = AI_REVIEW_LOCK
        .split_once("\njobs:\n")
        .expect("generated workflow jobs section is missing");
    let workflow_permissions = workflow_header
        .lines()
        .filter(|line| line.starts_with("permissions:"))
        .collect::<Vec<_>>();
    assert_eq!(workflow_permissions, ["permissions: {}"]);
    assert_eq!(AI_REVIEW_LOCK.matches("contents: write").count(), 0);
    assert_eq!(AI_REVIEW_LOCK.matches("pull-requests: write").count(), 2);
    assert_eq!(AI_REVIEW_LOCK.matches("issues: write").count(), 3);
    let jobs = job_names(AI_REVIEW_LOCK);
    assert_eq!(
        jobs,
        [
            "activation",
            "agent",
            "conclusion",
            "detection",
            "pre_activation",
            "safe_outputs"
        ]
    );
    let mut actual_write_permissions = BTreeSet::new();
    for name in jobs {
        actual_write_permissions.extend(job_write_permissions(AI_REVIEW_LOCK, &name));
    }
    let expected_write_permissions = BTreeSet::from([
        "activation:issues".to_owned(),
        "conclusion:issues".to_owned(),
        "conclusion:pull-requests".to_owned(),
        "safe_outputs:issues".to_owned(),
        "safe_outputs:pull-requests".to_owned(),
    ]);
    assert_eq!(actual_write_permissions, expected_write_permissions);
    let activation = job_block(AI_REVIEW_LOCK, "activation");
    assert!(activation.contains("GH_AW_BLOCKED_VERSION_REPORT_AS_ISSUE: \"true\""));
    assert!(activation.contains("Check compile-agentic version"));

    for key in [
        "GH_AW_SAFE_OUTPUTS_CONFIG",
        "GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG",
    ] {
        let config = lock_json_env(key);
        assert_eq!(
            config["submit_pull_request_review"]["allowed_events"],
            serde_json::json!(["COMMENT"]),
            "generated review decision policy changed in {key}"
        );
        assert_eq!(config["submit_pull_request_review"]["max"], 1);
    }
    let metadata = lock_multiline_json_env("GH_AW_TOOLS_META_JSON");
    assert_eq!(
        metadata["property_injections"]["submit_pull_request_review"]["event"]["enum"],
        serde_json::json!(["COMMENT"])
    );
}

#[test]
fn issue_triage_safe_outputs_do_not_receive_pull_request_write() {
    let source = frontmatter(ISSUE_TRIAGE_SOURCE);
    assert!(
        source.contains("  add-labels:\n    issues: true\n    pull-requests: false\n    allowed:")
    );
    assert!(
        source.contains("  add-comment:\n    issues: true\n    pull-requests: false\n    max: 1")
    );

    let (header, _) = ISSUE_TRIAGE_LOCK
        .split_once("\njobs:\n")
        .expect("generated issue-triage jobs section is missing");
    assert!(header.lines().any(|line| line == "permissions: {}"));
    assert_eq!(ISSUE_TRIAGE_LOCK.matches("pull-requests: write").count(), 0);

    let actual_write_permissions = job_names(ISSUE_TRIAGE_LOCK)
        .into_iter()
        .flat_map(|name| job_write_permissions(ISSUE_TRIAGE_LOCK, &name))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_write_permissions,
        BTreeSet::from([
            "activation:issues".to_owned(),
            "conclusion:issues".to_owned(),
            "safe_outputs:issues".to_owned(),
        ])
    );
    let agent = job_block(ISSUE_TRIAGE_LOCK, "agent");
    assert!(agent.contains("issues: read"));
    assert!(agent.contains("contents: read"));
}
