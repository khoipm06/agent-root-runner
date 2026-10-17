#!/usr/bin/env bash
# ==============================================================================
# Agent Root Runner - Comprehensive E2E Automated Test Runner
#
# Runs the full 4-tier requirement-driven E2E test suite in user space
# with zero sudo password prompts.
#
# Usage:
#   ./tests/test_runner.sh [OPTIONS]
#
# Options:
#   --all         Run all 4 test tiers (default)
#   --tier1       Run Tier 1 Feature Coverage tests only
#   --tier2       Run Tier 2 Boundary & Corner Cases only
#   --tier3       Run Tier 3 Cross-Feature Combinations only
#   --tier4       Run Tier 4 Real-World Application Scenarios only
#   -v, --verbose Enable verbose test output
#   -h, --help    Show this help message
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Temporary test workspace
TEST_TMPDIR=$(mktemp -d "/tmp/agent_root_runner_test_XXXXXX")
export AGENT_ROOT_RUNNER_SOCKET="$TEST_TMPDIR/runner.sock"
export AGENT_ROOT_RUNNER_AUDIT_LOG="$TEST_TMPDIR/audit.log"
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

CLEANUP_CALLED=0
cleanup() {
    if [ "$CLEANUP_CALLED" -eq 1 ]; then
        return
    fi
    CLEANUP_CALLED=1
    # Terminate any leftover background processes from this test run
    if [ -d "$TEST_TMPDIR" ]; then
        rm -rf "$TEST_TMPDIR"
    fi
}
trap cleanup EXIT INT TERM

# Default options
TARGET_TIER="all"
VERBOSE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            TARGET_TIER="all"
            shift
            ;;
        --tier1)
            TARGET_TIER="tier1"
            shift
            ;;
        --tier2)
            TARGET_TIER="tier2"
            shift
            ;;
        --tier3)
            TARGET_TIER="tier3"
            shift
            ;;
        --tier4)
            TARGET_TIER="tier4"
            shift
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--all|--tier1|--tier2|--tier3|--tier4] [-v|--verbose]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--all|--tier1|--tier2|--tier3|--tier4] [-v|--verbose]" >&2
            exit 1
            ;;
    esac
done

echo "===================================================================="
echo " Agent Root Runner - Automated E2E Test Suite"
echo " Project Root: $PROJECT_ROOT"
echo " Test Workspace: $TEST_TMPDIR"
echo " Target Tier: $TARGET_TIER"
echo "===================================================================="

run_test_module() {
    local module="$1"
    local title="$2"
    echo ""
    echo ">> Running $title ($module)..."
    python3 -m unittest "$module" $VERBOSE
}

FAILED=0

case "$TARGET_TIER" in
    tier1)
        run_test_module "tests.e2e.test_tier1_features" "Tier 1: Feature Coverage" || FAILED=1
        ;;
    tier2)
        run_test_module "tests.e2e.test_tier2_boundaries" "Tier 2: Boundary & Corner Cases" || FAILED=1
        ;;
    tier3)
        run_test_module "tests.e2e.test_tier3_combinations" "Tier 3: Cross-Feature Combinations" || FAILED=1
        ;;
    tier4)
        run_test_module "tests.e2e.test_tier4_scenarios" "Tier 4: Real-World Application Scenarios" || FAILED=1
        ;;
    all)
        run_test_module "tests.e2e.test_tier1_features" "Tier 1: Feature Coverage" || FAILED=1
        run_test_module "tests.e2e.test_tier2_boundaries" "Tier 2: Boundary & Corner Cases" || FAILED=1
        run_test_module "tests.e2e.test_tier3_combinations" "Tier 3: Cross-Feature Combinations" || FAILED=1
        run_test_module "tests.e2e.test_tier4_scenarios" "Tier 4: Real-World Application Scenarios" || FAILED=1
        ;;
esac

echo ""
echo "===================================================================="
if [ "$FAILED" -eq 0 ]; then
    echo " RESULT: ALL TESTS PASSED SUCCESSFULLY (100% PASS RATE)"
    echo "===================================================================="
    exit 0
else
    echo " RESULT: TEST FAILURES DETECTED"
    echo "===================================================================="
    exit 1
fi
