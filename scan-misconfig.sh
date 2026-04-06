#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-misconfig.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i r0binak/cve-2024-21626:v4
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar

# Examples
# https://www.docker.com/blog/docker-security-advisory-multiple-vulnerabilities-in-runc-buildkit-and-moby/
# https://github.com/snyk/leaky-vessels-static-detector/blob/main/internal/rules/rules.go
# ./scan-misconfig.sh -i r0binak/cve-2024-21626:v4
#
# https://github.com/bgeesaman/malicious-compliance
# ./scan-misconfig.sh -i megabreit/maliciouscompliance:1-os
#
# https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2
# https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r
# https://nvidia.custhelp.com/app/answers/detail/a_id/5659

set -Eeo pipefail

RULE_ID=(
    "cve-2024-21626-proc-fd"
    "cve-2024-23651-buildkit-cache-mount"
    "cve-2024-23652-buildkit-mount"
    "cve-2024-23653-buildkit-syntax"
    "malicious-compliance-os-detection"
    "malicious-compliance-hide-deps"
    "malicious-compliance-upx"
    "cve-2024-0132-libnvidia"
    "cve-2024-0132-libdxcore"
    "cve-2025-31133-dev-null"
    "cve-2025-52565-dev-console"
    "cve-2025-23267-ldcache-link"
)
RULE_SCOPE=(
    "json"
    "json"
    "json"
    "json"
    "json"
    "json"
    "json"
    "json"
    "json"
    "layer"
    "layer"
    "layer"
)
RULE_PATTERN=(
    "/proc/(1|self)/fd/"
    "\\--mount=type=cache"
    "\\--mount"
    "#*syntax=*docker*"
    "/etc/*-release"
    "ln\\S+\\.json|\\S+\\.lock|ln\\S+\\.txt"
    "\\supx\\s"
    "ln .*libnvidia"
    "ln .*libdxcore.so"
    "^[^c].*[[:space:]](\\./)?dev/null([[:space:]]|$| -> )"
    "^[^c].*[[:space:]](\\./)?dev/console([[:space:]]|$| -> )"
    "^[lh].*[[:space:]](\\./)?etc/ld\\.so\\.cache([[:space:]]|$| -> )"
)
RULE_MESSAGE=(
    "CVE-2024-21626 runC Escape"
    "CVE-2024-23651 BuildKit cache mounts"
    "CVE-2024-23652 BuildKit mount stub cleaner"
    "CVE-2024-23653 BuildKit API entitlements bypass"
    "malicious-compliance - attempt to avoid OS detection"
    "malicious-compliance - hide language dependency files"
    "malicious-compliance - UPX detected"
    "CVE-2024-0132 NVIDIA container toolkit escape"
    "CVE-2024-0132 NVIDIA container toolkit escape"
    "CVE-2025-31133 suspicious /dev/null replacement in layer"
    "CVE-2025-52565 suspicious /dev/console replacement in layer"
    "CVE-2025-23267 suspicious /etc/ld.so.cache link in layer"
)
RULE_URL=(
    "https://nitroc.org/en/posts/cve-2024-21626-illustrated/"
    "https://github.com/advisories/GHSA-m3r6-h7wv-7xxv"
    "https://github.com/advisories/GHSA-4v98-7qmw-rqr8"
    "https://github.com/advisories/GHSA-wr6v-9f75-vh2g"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-1-os"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-3-lang"
    "https://github.com/bgeesaman/malicious-compliance/blob/main/docker/Dockerfile-4-bin"
    "https://github.com/ctrsploit/ctrsploit/tree/public/vul/cve-2024-0132"
    "https://github.com/r0binak/CVE-2024-0132"
    "https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2"
    "https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r"
    "https://nvidia.custhelp.com/app/answers/detail/a_id/5659"
)

# var init
DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
LOCAL_FILE=''
MISCONFIG_RESULT_MESSAGE=''
MISCONFIG_RESULT=false
WHITELISTED_RULES_MESSAGE=''
IS_ANY_RULE_WHITELISTED=false

C_RED='\033[0;31m'
C_NIL='\033[0m'

EMOJI_DOCKER='\U1F433' # whale

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${PISC_OUT_DIR:=/tmp}"
# check debug mode to debug child scripts
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

RES_FILE=$PISC_OUT_DIR'/scan-misconfig.result'
LAYER_LIST_FILE=$PISC_OUT_DIR'/scan-misconfig.layers'
rm -f "$RES_FILE" "$LAYER_LIST_FILE"
touch "$RES_FILE"

declare -a RULE_TRIGGERED
for (( i=0; i<${#RULE_ID[@]}; i++ ));
do
    RULE_TRIGGERED+=("false")
done

run_child_script()
{
    local script_path="$1"
    shift

    if [ -n "$DEBUG" ]; then
        /bin/bash -x "$script_path" "$@"
    else
        /bin/bash "$script_path" "$@"
    fi
}

# extract options and their arguments into variables.
while [ $# -gt 0 ]; do
    case "$1" in
        --dont-output-result)
            DONT_OUTPUT_RESULT=true
            shift 1
            ;;
        -i|--image)
            if [ -z "${2:-}" ]; then
                echo "Wrong usage! Try '$0 --help' for more information."
                exit 2
            fi
            IMAGE_LINK=$2
            shift 2
            ;;
        --tar)
            if [ -z "${2:-}" ]; then
                echo "Wrong usage! Try '$0 --help' for more information."
                exit 2
            fi
            LOCAL_FILE=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

append_rule_message()
{
    local rule_index="$1"
    local evidence="$2"

    MISCONFIG_RESULT=true
    MISCONFIG_RESULT_MESSAGE="${MISCONFIG_RESULT_MESSAGE}"$'\n'"   ${RULE_ID[$rule_index]} - ${RULE_MESSAGE[$rule_index]}"$'\n'"     ${RULE_URL[$rule_index]}"
    if [ -n "$evidence" ]; then
        MISCONFIG_RESULT_MESSAGE="${MISCONFIG_RESULT_MESSAGE}"$'\n'"     evidence: $evidence"
    fi
}

append_whitelist_message()
{
    local rule_index="$1"

    IS_ANY_RULE_WHITELISTED=true
    WHITELISTED_RULES_MESSAGE="${WHITELISTED_RULES_MESSAGE}"$'\n'"   ${RULE_ID[$rule_index]} whitelisted"
}

handle_rule_match()
{
    local rule_index="$1"
    local evidence="$2"
    local exclusion_result=0

    if [ "${RULE_TRIGGERED[$rule_index]}" = "true" ]; then
        return 0
    fi
    RULE_TRIGGERED[rule_index]="true"

    set +e
    run_child_script "$SCRIPTPATH/check-exclusions.sh" -i "$IMAGE_LINK" --misconfig "${RULE_ID[$rule_index]}"
    exclusion_result=$?
    set -e

    if [ $exclusion_result -eq 1 ]; then
        append_whitelist_message "$rule_index"
        return 0
    fi
    if [ $exclusion_result -ne 0 ]; then
        exit $exclusion_result
    fi

    append_rule_message "$rule_index" "$evidence"
}

scan_json_rules()
{
    local json_file=''
    local evidence=''

    for json_file in "$PISC_OUT_DIR/image"/*.json
    do
        [ -f "$json_file" ] || continue
        for (( i=0; i<${#RULE_ID[@]}; i++ ));
        do
            if [ "${RULE_SCOPE[$i]}" != "json" ]; then
                continue
            fi
            if grep -Eqi "${RULE_PATTERN[$i]}" "$json_file"; then
                evidence=$(grep -Eim1 "${RULE_PATTERN[$i]}" "$json_file" | tr -d '\r')
                handle_rule_match "$i" "$(basename "$json_file"): $evidence"
            fi
        done
    done
}

scan_layer_rules()
{
    local layer_file=''
    local evidence=''

    for layer_file in "$PISC_OUT_DIR/image"/*.tar
    do
        [ -f "$layer_file" ] || continue
        tar -tvf "$layer_file" > "$LAYER_LIST_FILE"
        for (( i=0; i<${#RULE_ID[@]}; i++ ));
        do
            if [ "${RULE_SCOPE[$i]}" != "layer" ]; then
                continue
            fi
            if grep -Eqi "${RULE_PATTERN[$i]}" "$LAYER_LIST_FILE"; then
                evidence=$(grep -Eim1 "${RULE_PATTERN[$i]}" "$LAYER_LIST_FILE" | tr -d '\r')
                handle_rule_match "$i" "$(basename "$layer_file"): $evidence"
            fi
        done
    done
}

# download and unpack image or use cache
if [ -n "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    run_child_script "$SCRIPTPATH/scan-download-unpack.sh" --tar "$LOCAL_FILE"
else
    run_child_script "$SCRIPTPATH/scan-download-unpack.sh" -i "$IMAGE_LINK"
fi

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan misconfiguration\033[0K\r"

scan_json_rules
scan_layer_rules

# result: output to console and write to file
if [ "$MISCONFIG_RESULT" = true ]; then
    MISCONFIG_RESULT_MESSAGE="$EMOJI_DOCKER $C_RED$IMAGE_LINK$C_NIL >>> detected dangerous misconfiguration$MISCONFIG_RESULT_MESSAGE"
    if [ "$IS_ANY_RULE_WHITELISTED" = true ]; then
        MISCONFIG_RESULT_MESSAGE="${MISCONFIG_RESULT_MESSAGE}"$'\n'"   whitelisted rules:${WHITELISTED_RULES_MESSAGE}"
    fi
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo -e "$MISCONFIG_RESULT_MESSAGE"
    fi
    echo "$MISCONFIG_RESULT_MESSAGE" > "$RES_FILE"
else
    if [ "$IS_ANY_RULE_WHITELISTED" = true ]; then
        if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
            echo -e "$IMAGE_LINK >>> OK (whitelisted)                      "
        fi
        echo "OK (whitelisted)" > "$RES_FILE"
    else
        if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
            echo "$IMAGE_LINK >>> OK                        "
        fi
        echo "OK" > "$RES_FILE"
    fi
fi

rm -f "$LAYER_LIST_FILE"

exit 0
