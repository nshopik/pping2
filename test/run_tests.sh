#!/bin/sh
# run_tests.sh — master test runner for pping
#
# Usage:
#   cd test && sh run_tests.sh
#   make check          (from repo root — preferred)
#
# Exit status: 0 if all tests passed, 1 if any test failed.
# Each individual test script must exit 0 for PASS, non-zero for FAIL.

# Colour support when stdout is a terminal
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    RESET='\033[0m'
else
    GREEN=''
    RED=''
    RESET=''
fi

PASS_COUNT=0
FAIL_COUNT=0

run_test() {
    script="$1"
    name=$(basename "$script" .sh)

    sh "$script"
    rc=$?

    if [ $rc -eq 0 ]; then
        printf "${GREEN}PASS${RESET} %s\n" "$name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf "${RED}FAIL${RESET} %s (exit %d)\n" "$name" "$rc"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# Determine the directory this script lives in so we can find sibling scripts
# regardless of the working directory the caller used.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Unit tests (compiled binary)
if [ -x "$SCRIPT_DIR/unit_tests" ]; then
    "$SCRIPT_DIR/unit_tests"
    rc=$?
    if [ $rc -eq 0 ]; then
        printf "${GREEN}PASS${RESET} unit_tests\n"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf "${RED}FAIL${RESET} unit_tests (exit %d)\n" "$rc"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
else
    printf "${RED}FAIL${RESET} unit_tests (binary not found: %s/unit_tests)\n" "$SCRIPT_DIR"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Shell-based test scripts
run_test "$SCRIPT_DIR/test_integration.sh"
run_test "$SCRIPT_DIR/test_format.sh"
run_test "$SCRIPT_DIR/test_seq.sh"
run_test "$SCRIPT_DIR/cross_mode_check.sh"
run_test "$SCRIPT_DIR/test_cli.sh"
run_test "$SCRIPT_DIR/test_aggregate.sh"

# Summary
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo ""
echo "Results: $PASS_COUNT/$TOTAL passed"

if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
exit 0
