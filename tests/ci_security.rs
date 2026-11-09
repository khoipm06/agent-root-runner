use std::collections::BTreeSet;

const WORKFLOW: &str = include_str!("../.github/workflows/ci.yml");
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
