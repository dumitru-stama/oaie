//! Integration tests for the `oaie-agent` library crate (`OaieClient`)
//! and the `oaie-mcp` JSON-RPC protocol.

use std::io::Read;

use oaie_agent::OaieClient;
use oaie_cas::store::CasStore;
use oaie_core::backend::BackendKind;
use oaie_core::hash_algo::HashAlgorithm;
use oaie_db::OaieDb;
use oaie_tests::setup_store;

// ── OaieClient integration ──

#[test]
fn client_run_echo() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let result = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare)
        .run(&["echo", "hello"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.duration_secs > 0.0);
    assert!(result.stdout.size_bytes > 0);
    assert_eq!(result.isolation.backend, "bare");
    assert!(!result.run_id.is_empty());
    assert!(!result.manifest_hash.is_empty());
}

#[test]
fn client_run_captures_stdout_content() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let result = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare)
        .run(&["echo", "agent output"])
        .unwrap();

    // Verify the stdout hash resolves to actual content in CAS.
    let cas = CasStore::new(store.cas_dir.clone(), HashAlgorithm::Blake3);
    let hash = oaie_core::artifact::Hash::from_hex(&result.stdout.hash).unwrap();
    let mut file = cas.open(&hash).unwrap();
    let mut content = Vec::new();
    file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"agent output\n");
}

#[test]
fn client_run_nonzero_exit() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let result = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare)
        .run(&["false"])
        .unwrap();

    assert_eq!(result.exit_code, 1);
}

#[test]
fn client_verify_after_run() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    let result = client.run(&["echo", "verify me"]).unwrap();

    // Verify the run we just created.
    let report = client.verify(&result.run_id).unwrap();
    assert!(report.passed, "verify should pass: {}", report.summary);
    assert!(!report.checks.is_empty());
}

#[test]
fn client_verify_last() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    client.run(&["echo", "first"]).unwrap();

    // "last" should resolve to the most recent run.
    let report = client.verify("last").unwrap();
    assert!(report.passed);
}

#[test]
fn client_read_output_stdout() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    let result = client.run(&["echo", "read me"]).unwrap();

    let bytes = client.read_output(&result.run_id, "stdout").unwrap();
    assert_eq!(bytes, b"read me\n");
}

#[test]
fn client_read_output_stderr() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    let result = client
        .run(&["sh", "-c", "echo err >&2"])
        .unwrap();

    let bytes = client.read_output(&result.run_id, "stderr").unwrap();
    assert_eq!(bytes, b"err\n");
}

#[test]
fn client_read_output_not_found() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    let result = client.run(&["echo", "hi"]).unwrap();

    let err = client.read_output(&result.run_id, "nonexistent");
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("nonexistent"), "error should mention the name: {msg}");
}

#[test]
fn client_default_policy_is_agent_safe() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    // Default policy is agent-safe — should still work for basic echo.
    let result = OaieClient::new(&store_path)
        .backend(BackendKind::Bare)
        .run(&["echo", "default policy"])
        .unwrap();

    assert_eq!(result.exit_code, 0);
}

#[test]
fn client_db_records_run() {
    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare)
        .run(&["echo", "db test"])
        .unwrap();

    // Verify the run was recorded in the database.
    let db = OaieDb::open(&store.db_path).unwrap();
    let run = db.get_latest_run().unwrap().unwrap();
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(run.command, vec!["echo", "db test"]);
}

// ── MCP protocol tests ──

#[test]
fn mcp_initialize_response() {
    let result = oaie_mcp::jsonrpc::initialize_result();
    assert_eq!(result["protocolVersion"], "2024-11-05");
    assert!(result["capabilities"]["tools"].is_object());
    assert_eq!(result["serverInfo"]["name"], "oaie-mcp");
}

#[test]
fn mcp_tools_list_has_three_tools() {
    let result = oaie_mcp::jsonrpc::tools_list();
    let tools = result["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);

    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"oaie_run"));
    assert!(names.contains(&"oaie_verify"));
    assert!(names.contains(&"oaie_read_output"));
}

#[test]
fn mcp_tool_schemas_have_required_fields() {
    let result = oaie_mcp::jsonrpc::tools_list();
    let tools = result["tools"].as_array().unwrap();

    for tool in tools {
        assert!(tool["name"].is_string(), "tool should have name");
        assert!(tool["description"].is_string(), "tool should have description");
        assert!(tool["inputSchema"].is_object(), "tool should have inputSchema");
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"]["required"].is_array(), "tool should have required");
    }
}

#[test]
fn mcp_oaie_run_schema_requires_command() {
    let result = oaie_mcp::jsonrpc::tools_list();
    let tools = result["tools"].as_array().unwrap();
    let run_tool = tools.iter().find(|t| t["name"] == "oaie_run").unwrap();

    let required = run_tool["inputSchema"]["required"].as_array().unwrap();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0], "command");

    // Should have optional params.
    let props = run_tool["inputSchema"]["properties"].as_object().unwrap();
    assert!(props.contains_key("policy"));
    assert!(props.contains_key("backend"));
    assert!(props.contains_key("timeout"));
    assert!(props.contains_key("network"));
}

#[test]
fn mcp_handle_unknown_tool() {
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "nonexistent_tool",
        &serde_json::json!({}),
        "/tmp",
    );
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, -32601); // METHOD_NOT_FOUND
}

#[test]
fn mcp_handle_run_missing_command() {
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_run",
        &serde_json::json!({}),
        "/tmp",
    );
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, -32602); // INVALID_PARAMS
}

#[test]
fn mcp_handle_run_invalid_command_type() {
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_run",
        &serde_json::json!({"command": [1, 2]}),
        "/tmp",
    );
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32602);
    assert!(err.message.contains("strings"));
}

#[test]
fn mcp_handle_verify_missing_run_id() {
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_verify",
        &serde_json::json!({}),
        "/tmp",
    );
    assert!(resp.error.is_some());
    assert_eq!(resp.error.unwrap().code, -32602);
}

#[test]
fn mcp_handle_read_output_missing_params() {
    // Missing both params.
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_read_output",
        &serde_json::json!({}),
        "/tmp",
    );
    assert!(resp.error.is_some());

    // Missing artifact_name.
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_read_output",
        &serde_json::json!({"run_id": "abc"}),
        "/tmp",
    );
    assert!(resp.error.is_some());
}

#[test]
fn mcp_handle_run_empty_command() {
    let resp = oaie_mcp::tools::handle_tool_call(
        Some(serde_json::json!(1)),
        "oaie_run",
        &serde_json::json!({"command": []}),
        "/tmp",
    );
    assert!(resp.error.is_some());
    let err = resp.error.unwrap();
    assert_eq!(err.code, -32602); // INVALID_PARAMS
    assert!(
        err.message.contains("empty"),
        "error should mention empty: {}",
        err.message
    );
}

#[test]
fn mcp_initialize_validates_protocol() {
    // The initialize result should contain the expected protocol version.
    let result = oaie_mcp::jsonrpc::initialize_result();
    assert_eq!(result["protocolVersion"], "2024-11-05");

    // Server name matches.
    assert_eq!(result["serverInfo"]["name"], "oaie-mcp");
}

#[test]
fn client_run_job_with_timeout() {
    use std::time::Duration;

    let (store, _dir) = setup_store();
    let store_path = store.root.display().to_string();

    let job = oaie_core::job::JobSpec {
        command: vec!["echo".into(), "timeout test".into()],
        inputs: None,
        outputs: None,
        network: false,
        trace: Default::default(),
        timeout: Some(Duration::from_secs(30)),
        policy: None,
        extra_ro: vec![],
        extra_rw: vec![],
        no_isolation: true,
        backend: BackendKind::Bare,
        interactive: false,
    };

    let client = OaieClient::new(&store_path)
        .policy("safe")
        .backend(BackendKind::Bare);

    let result = client.run_job(&job).unwrap();
    assert_eq!(result.exit_code, 0);
    assert!(result.duration_secs > 0.0);
}
