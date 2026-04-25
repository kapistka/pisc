#!/bin/bash
# Public OCI-Image Security Checker
# Author: drybalka-s, 2026

set -Eeo pipefail

IMAGE="${1:-peru/malware-cryptominer-container:3}"

if [[ -z "${VT_API_KEY:-}" ]]; then
    echo "VT_API_KEY not found"
    exit 2
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

OUT_BEFORE="$TMP_DIR/out-before"
OUT_AFTER="$TMP_DIR/out-after"
RAW_BEFORE="$TMP_DIR/raw-before"
RAW_AFTER="$TMP_DIR/raw-after"
WHITELIST_FILE="$TMP_DIR/whitelist.yaml"
NO_EXCLUSIONS_FILE="$TMP_DIR/no-exclusions.yaml"
BEFORE_LOG="$TMP_DIR/before.txt"
AFTER_LOG="$TMP_DIR/after.txt"

mkdir -p "$OUT_BEFORE" "$OUT_AFTER" "$RAW_BEFORE" "$RAW_AFTER"

run_scan() {
    export PISC_OUT_DIR="$1"
    export PISC_VT_ARTIFACTS_DIR="$2"
    export PISC_EXCLUSIONS_FILE="$3"

    set +e
    /bin/bash ./scan-virustotal.sh --dont-adv-search --virustotal-key "$VT_API_KEY" -i "$IMAGE"
    RC=$?
    set -e

    return $RC
}

run_scan "$OUT_BEFORE" "$RAW_BEFORE" "$NO_EXCLUSIONS_FILE" > "$BEFORE_LOG" 2>&1

if ! grep -q "virustotal detected malicious file" "$BEFORE_LOG"; then
    echo "Baseline run did not detect malware"
    exit 2
fi

SOURCE_JSON=''
for f in "$RAW_BEFORE"/hash-search-*.json; do
    if [[ -f "$f" ]] && [[ "$(jq -r '[.data[]?.attributes?.last_analysis_results?[]? | select(.category == "malicious")] | length' "$f")" -gt 0 ]]; then
        SOURCE_JSON="$f"
        break
    fi
done

if [[ -z "$SOURCE_JSON" ]]; then
    echo "No malicious VirusTotal hash-search response found"
    exit 2
fi

{
    echo "- image:"
    echo "    - \"$IMAGE\""
    echo "  virustotal-engine:"
    jq -r '.data[]?.attributes?.last_analysis_results?[]? | select(.category == "malicious") | .engine_name' "$SOURCE_JSON" \
        | sort -u \
        | sed 's/^/    - "/; s/$/"/'
} > "$WHITELIST_FILE"

run_scan "$OUT_AFTER" "$RAW_AFTER" "$WHITELIST_FILE" > "$AFTER_LOG" 2>&1

if ! grep -q ">>> OK" "$AFTER_LOG"; then
    echo "Whitelisted run did not return OK"
    exit 2
fi

echo "Artifacts: $TMP_DIR"
echo "Source JSON: $(basename "$SOURCE_JSON")"
echo "Test passed!"
