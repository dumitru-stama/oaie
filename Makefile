.PHONY: build test clippy check clean run install test-sandbox test-e2e bpf build-ebpf test-ebpf clippy-ebpf build-guest build-firecracker test-firecracker clippy-firecracker build-mcp test-mcp build-netpol test-netpol check-all

# Default: build + clippy + test
all: build clippy test

build:
	cargo build --workspace

test:
	@# Unit/lib tests (no process spawning) run in parallel for speed.
	cargo test --workspace --exclude oaie-tests
	@# Integration tests that don't spawn namespace sandboxes: parallel.
	@# OAIE_NO_SIGNAL_HANDLERS prevents the runner's signal handler from
	@# overriding SIGINT, which would make the test binary immune to Ctrl+C.
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- \
		--skip runner_e2e \
		--skip adversarial \
		--skip sandbox_tests \
		--skip parity_ \
		--skip trace_tests \
		--skip verify_tests \
		--skip interactive_tests \
		--skip signing_tests \
		--skip session_tests \
		--skip stress_tests \
		--skip v03_integration_tests \
		--skip backward_compat_tests
	@# Namespace-heavy tests (clone + mounts + ptrace): serial to avoid
	@# kernel lock contention on namespace/mount creation. Running 64+
	@# namespace tests in parallel causes 100x+ slowdown from lock
	@# contention in the kernel mount and namespace subsystems.
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- adversarial --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- sandbox_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- parity_ --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- trace_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- verify_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- signing_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- interactive_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- session_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- stress_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- v03_integration_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- backward_compat_tests --test-threads=1
	@# runner_e2e tests spawn sandbox children via clone() which leaks
	@# pipe fds to concurrent clone() calls in the same process. In
	@# production each oaie run is a separate process so this doesn't
	@# apply.
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests -- runner_e2e --test-threads=1

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# build + clippy + test in one shot
check: build clippy test

clean:
	cargo clean

# Build release binary
release:
	cargo build --workspace --release

# Run the CLI (pass ARGS, e.g. make run ARGS="init")
ARGS ?= --help
run:
	cargo run -- $(ARGS)

# Install to ~/.cargo/bin
install:
	cargo install --path crates/oaie-cli

# Sandbox crate tests only (probe + seccomp + sandbox)
test-sandbox:
	cargo test -p oaie-sandbox

# End-to-end runner tests (includes sandboxed execution)
test-e2e:
	cargo test -p oaie-cli --test run_e2e

# ── eBPF targets ──

# Compile BPF programs with clang (requires clang, bpftool, libbpf headers)
bpf:
	$(MAKE) -C bpf

# Build all crates with the ebpf feature enabled
build-ebpf:
	cargo build --workspace --features ebpf

# Run all tests with the ebpf feature enabled
test-ebpf:
	cargo test --workspace --features ebpf --exclude oaie-tests
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- \
		--skip runner_e2e \
		--skip adversarial \
		--skip sandbox_tests \
		--skip parity_ \
		--skip trace_tests \
		--skip verify_tests \
		--skip interactive_tests \
		--skip signing_tests \
		--skip session_tests \
		--skip stress_tests \
		--skip v03_integration_tests \
		--skip backward_compat_tests
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- adversarial --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- sandbox_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- parity_ --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- trace_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- verify_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- signing_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- interactive_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- session_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- stress_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- v03_integration_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- backward_compat_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features ebpf -- runner_e2e --test-threads=1

# Run clippy with the ebpf feature enabled
clippy-ebpf:
	cargo clippy --workspace --features ebpf --all-targets -- -D warnings

# ── Firecracker targets ──

# Build the guest agent as a static musl binary
build-guest:
	cargo build -p oaie-guest --target x86_64-unknown-linux-musl --release

# Build all crates with the firecracker feature enabled
build-firecracker:
	cargo build --workspace --features firecracker

# Run all tests with the firecracker feature enabled
test-firecracker:
	cargo test --workspace --features firecracker --exclude oaie-tests
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- \
		--skip runner_e2e \
		--skip adversarial \
		--skip sandbox_tests \
		--skip parity_ \
		--skip trace_tests \
		--skip verify_tests \
		--skip interactive_tests \
		--skip signing_tests \
		--skip session_tests \
		--skip stress_tests \
		--skip v03_integration_tests \
		--skip backward_compat_tests
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- adversarial --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- sandbox_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- parity_ --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- trace_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- verify_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- signing_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- interactive_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- session_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- stress_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- v03_integration_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- backward_compat_tests --test-threads=1
	OAIE_NO_SIGNAL_HANDLERS=1 cargo test -p oaie-tests --features firecracker -- runner_e2e --test-threads=1

# Run clippy with the firecracker feature enabled
clippy-firecracker:
	cargo clippy --workspace --features firecracker --all-targets -- -D warnings

# ── MCP / Agent targets ──

# Build the MCP server binary
build-mcp:
	cargo build -p oaie-mcp

# Test the agent library and MCP server
test-mcp:
	cargo test -p oaie-agent
	cargo test -p oaie-mcp
	cargo test -p oaie-tests -- structured_output
	cargo test -p oaie-tests -- agent_tests

# ── Network policy targets ──

# Build the network policy crate
build-netpol:
	cargo build -p oaie-netpol

# Test network policy (resolve, nftables gen, domain matching, DNS wire, SNI)
test-netpol:
	cargo test -p oaie-netpol
	cargo test -p oaie-tests -- netpol_tests

# ── Combined targets ──

# Build and test with all features
check-all: clippy clippy-ebpf clippy-firecracker test test-ebpf test-firecracker
