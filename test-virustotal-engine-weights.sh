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

NO_EXCLUSIONS_FILE="$TMP_DIR/no-exclusions.yaml"
mkdir -p "$TMP_DIR/default-out" "$TMP_DIR/threshold-out" "$TMP_DIR/weighted-out" "$TMP_DIR/raw-default"

run_scan() {
    local TARGET_FLAG="$3"
    local TARGET_VALUE="$4"

    set +e
    PISC_EXCLUSIONS_FILE="$NO_EXCLUSIONS_FILE" PISC_OUT_DIR="$1" PISC_VT_ARTIFACTS_DIR="${2:-}" \
        /bin/bash ./scan-virustotal.sh --dont-adv-search --virustotal-key "$VT_API_KEY" "$TARGET_FLAG" "$TARGET_VALUE"
    RC=$?
    set -e

    return $RC
}

run_scan "$TMP_DIR/default-out" "$TMP_DIR/raw-default" -i "$IMAGE" > "$TMP_DIR/default.txt" 2>&1

if ! grep -q "virustotal detected malicious file" "$TMP_DIR/default.txt"; then
    echo "Default policy did not detect malware"
    exit 2
fi

IMAGE_TAR="$TMP_DIR/default-out/image.tar"
if [[ ! -f "$IMAGE_TAR" ]]; then
    echo "Image tar not found after default scan"
    exit 2
fi

SOURCE_JSON=''
for f in "$TMP_DIR/raw-default"/hash-search-*.json; do
    if [[ -f "$f" ]] && [[ "$(jq -r '[.data[]?.attributes?.last_analysis_results?[]? | select(.category == "malicious")] | length' "$f")" -gt 0 ]]; then
        SOURCE_JSON="$f"
        break
    fi
done

if [[ -z "$SOURCE_JSON" ]]; then
    echo "No malicious VirusTotal hash-search response found"
    exit 2
fi

WEIGHTED_ENGINE=$(jq -r 'first(.data[]?.attributes?.last_analysis_results?[]? | select(.category == "malicious") | .engine_name)' "$SOURCE_JSON")

VT_ENGINE_SCORE_THRESHOLD=1000 run_scan "$TMP_DIR/threshold-out" "" --tar "$IMAGE_TAR" > "$TMP_DIR/threshold.txt" 2>&1

if ! grep -q ">>> OK" "$TMP_DIR/threshold.txt"; then
    echo "High threshold policy did not return OK"
    exit 2
fi

VT_ENGINE_WEIGHTS="$WEIGHTED_ENGINE=100" VT_ENGINE_SCORE_THRESHOLD=100 run_scan "$TMP_DIR/weighted-out" "" --tar "$IMAGE_TAR" > "$TMP_DIR/weighted.txt" 2>&1

if ! grep -q "virustotal detected malicious file" "$TMP_DIR/weighted.txt"; then
    echo "Weighted engine policy did not detect malware"
    exit 2
fi

echo "Weighted engine: $WEIGHTED_ENGINE"
echo "Test passed!"
