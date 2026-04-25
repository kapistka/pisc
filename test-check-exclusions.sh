#!/bin/bash
# Public OCI-Image Security Checker
# Author: drybalka-s, 2026

set -Eeo pipefail

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

export PISC_OUT_DIR="$TMP_DIR/out"
export PISC_EXCLUSIONS_FILE="$TMP_DIR/whitelist.yaml"
mkdir -p "$PISC_OUT_DIR"

cat > "$PISC_EXCLUSIONS_FILE" <<EOF
- image:
    - "example/app:*"
  virustotal-engine:
    - "TrendMicro-HouseCall"
    - "Bkav Pro"
EOF

assert_exit_code() {
    EXPECTED=$1
    shift

    set +e
    /bin/bash ./check-exclusions.sh "$@"
    ACTUAL=$?
    set -e

    if [[ "$ACTUAL" -ne "$EXPECTED" ]]; then
        echo "Unexpected exit code: $ACTUAL"
        echo "Expected: $EXPECTED"
        echo "Command: ./check-exclusions.sh $*"
        exit 2
    fi
}

assert_exit_code 1 -i example/app:1.0 --virustotal-engine TrendMicro-HouseCall
assert_exit_code 1 -i example/app:1.0 --virustotal-engine "Bkav Pro"
assert_exit_code 0 -i example/app:1.0 --virustotal-engine OtherEngine
assert_exit_code 0 -i other/app:1.0 --virustotal-engine TrendMicro-HouseCall

echo "Test passed!"
