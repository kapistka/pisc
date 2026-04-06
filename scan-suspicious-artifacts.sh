#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-suspicious-artifacts.sh [--dont-output-result] [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     -i, --image string                only this image will be checked. Example: -i alpine:latest
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar

# Notes
#     This module is warning-only. It does not classify files as malware.
#     It marks suspicious packaging indicators and launcher patterns:
#       - embedded archives in layers (.zip, .7z, .rar)
#       - packed binary hints by file name (.upx)
#       - suspicious shell launchers like "curl | sh", "wget | bash", "base64 -d | sh"
#     Embedded archive is only a pointer to an archive file inside the image.
#     It is suspicious and should be reviewed manually.

set -Eeo pipefail

DONT_OUTPUT_RESULT=false
IMAGE_LINK=''
LOCAL_FILE=''
HAS_FINDINGS=false
HAS_EXCLUDED_FINDINGS=false
RESULT_MESSAGE=''

C_NIL='\033[0m'
C_YLW='\033[0;33m'
EMOJI_WARN='\U26A0'

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
: "${PISC_OUT_DIR:=/tmp}"

IMAGE_DIR=$PISC_OUT_DIR'/image'
LAYER_TMP_DIR=$IMAGE_DIR'/0'
RES_FILE=$PISC_OUT_DIR'/scan-suspicious-artifacts.result'
TMP_MATCH_FILE=$PISC_OUT_DIR'/scan-suspicious-artifacts.tmp'
TMP_UNPACK_ERR_FILE=$PISC_OUT_DIR'/scan-suspicious-artifacts.unpack.err'
ERROR_FILE=$PISC_OUT_DIR'/scan-suspicious-artifacts.error'
TAR_BIN='tar'
USE_GNU_TAR_OPTIONS=false

rm -f "$RES_FILE" "$TMP_MATCH_FILE" "$TMP_UNPACK_ERR_FILE" "$ERROR_FILE"

error_exit()
{
    printf '   %s' "$1" > "$ERROR_FILE"
    exit 2
}

if command -v gtar >/dev/null 2>&1; then
    TAR_BIN='gtar'
fi
if "$TAR_BIN" --version 2>/dev/null | grep -q "GNU"; then
    USE_GNU_TAR_OPTIONS=true
fi

append_rule_finding()
{
    local layer_id="$1"
    local rule_id="$2"
    local kind="$3"
    local evidence="$4"
    local exclusion_exit_code=0

    set +e
    /bin/bash "$SCRIPTPATH/check-exclusions.sh" -i "$IMAGE_LINK" --suspicious "$rule_id" >/dev/null 2>&1
    exclusion_exit_code=$?
    set -e

    if [ "$exclusion_exit_code" -eq 1 ]; then
        HAS_EXCLUDED_FINDINGS=true
        return 0
    fi
    if [ "$exclusion_exit_code" -eq 2 ]; then
        error_exit "suspicious artifacts: exclusions check failed"
    fi

    HAS_FINDINGS=true
    RESULT_MESSAGE="${RESULT_MESSAGE}"$'\n'"   layer:${layer_id}"$'\n'"     ${kind} (${rule_id}): ${evidence}"
}

prepare_image()
{
    if [ -n "$LOCAL_FILE" ]; then
        /bin/bash "$SCRIPTPATH/scan-download-unpack.sh" --tar "$LOCAL_FILE"
    else
        /bin/bash "$SCRIPTPATH/scan-download-unpack.sh" -i "$IMAGE_LINK"
    fi
}

unpack_layer()
{
    local layer_file="$1"

    rm -rf "$LAYER_TMP_DIR" "$TMP_UNPACK_ERR_FILE"
    mkdir -p "$LAYER_TMP_DIR"

    set +e
    if [ "$USE_GNU_TAR_OPTIONS" = true ]; then
        "$TAR_BIN" --ignore-failed-read --one-file-system --no-same-owner --no-same-permissions --mode=+w --exclude dev/* -xf "$layer_file" -C "$LAYER_TMP_DIR" 2>"$TMP_UNPACK_ERR_FILE"
    else
        "$TAR_BIN" -xf "$layer_file" -C "$LAYER_TMP_DIR" 2>"$TMP_UNPACK_ERR_FILE"
    fi
    set -e

    find "$LAYER_TMP_DIR" -type d -exec chmod u+rwx {} + 2>/dev/null || true

    return 0
}

scan_layer_names()
{
    local layer_file="$1"
    local layer_id="$2"
    local entry=''

    while IFS= read -r entry; do
        case "$entry" in
            *.zip|*.ZIP|*.7z|*.7Z|*.rar|*.RAR)
                case "$entry" in
                    *.zip|*.ZIP)
                        append_rule_finding "$layer_id" "embedded-archive-zip" "embedded archive" "$entry"
                        ;;
                    *.7z|*.7Z)
                        append_rule_finding "$layer_id" "embedded-archive-7z" "embedded archive" "$entry"
                        ;;
                    *.rar|*.RAR)
                        append_rule_finding "$layer_id" "embedded-archive-rar" "embedded archive" "$entry"
                        ;;
                esac
                ;;
            *.upx|*.UPX)
                append_rule_finding "$layer_id" "packed-binary-hint-upx" "packed binary hint" "$entry"
                ;;
        esac
    done < <("$TAR_BIN" -tf "$layer_file" 2>/dev/null)
}

scan_layer_launchers()
{
    local layer_id="$1"
    local rule_id=''
    local evidence=''

    : > "$TMP_MATCH_FILE"
    grep -r -I -E -n \
        'curl[^[:cntrl:]]+\|[[:space:]]*(sh|bash)|wget[^[:cntrl:]]+\|[[:space:]]*(sh|bash)|base64[[:space:]]+-d[^[:cntrl:]]+\|[[:space:]]*(sh|bash)|openssl[[:space:]]+enc[^[:cntrl:]]+\|[[:space:]]*(sh|bash)' \
        "$LAYER_TMP_DIR" 2>/dev/null \
    | awk '
        /curl[^[:cntrl:]]+\|[[:space:]]*(sh|bash)/                    { print "launcher-curl-pipe-shell\t" $0 }
        /wget[^[:cntrl:]]+\|[[:space:]]*(sh|bash)/                    { print "launcher-wget-pipe-shell\t" $0 }
        /base64[[:space:]]+-d[^[:cntrl:]]+\|[[:space:]]*(sh|bash)/    { print "launcher-base64-pipe-shell\t" $0 }
        /openssl[[:space:]]+enc[^[:cntrl:]]+\|[[:space:]]*(sh|bash)/  { print "launcher-openssl-enc-pipe-shell\t" $0 }
    ' >> "$TMP_MATCH_FILE" || true

    while IFS=$'\t' read -r rule_id evidence; do
        [ -n "$rule_id" ] || continue
        append_rule_finding "$layer_id" "$rule_id" "suspicious launcher" "${evidence#"$LAYER_TMP_DIR"/}"
    done < "$TMP_MATCH_FILE"
}

scan_unpack_warnings()
{
    local layer_id="$1"
    local warn_line=''

    warn_line=$(head -n 1 "$TMP_UNPACK_ERR_FILE" 2>/dev/null || true)
    if [ -n "$warn_line" ]; then
        append_rule_finding "$layer_id" "unpack-warning" "unpack warning" "$warn_line"
    fi
}

# extract options and their arguments into variables
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

if [ -n "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
fi

prepare_image

for layer_file in "$IMAGE_DIR"/*.tar
do
    [ -f "$layer_file" ] || continue
    layer_name="${layer_file##*/}"
    layer_id="${layer_name%.*}"

    scan_layer_names "$layer_file" "${layer_id:0:8}"
    unpack_layer "$layer_file"
    scan_layer_launchers "${layer_id:0:8}"
    scan_unpack_warnings "${layer_id:0:8}"
done

rm -f "$TMP_MATCH_FILE" "$TMP_UNPACK_ERR_FILE"

if [ "$HAS_FINDINGS" = true ]; then
    RESULT_MESSAGE="$EMOJI_WARN $C_YLW$IMAGE_LINK$C_NIL >>> suspicious artifacts detected$RESULT_MESSAGE"
    if [ "$HAS_EXCLUDED_FINDINGS" = true ]; then
        RESULT_MESSAGE="${RESULT_MESSAGE}"$'\n'"   some suspicious detections are whitelisted"
    fi
    if [ "$DONT_OUTPUT_RESULT" = false ]; then
        echo -e "$RESULT_MESSAGE"
    fi
    echo "$RESULT_MESSAGE" > "$RES_FILE"
else
    if [ "$DONT_OUTPUT_RESULT" = false ]; then
        if [ "$HAS_EXCLUDED_FINDINGS" = true ]; then
            echo "$IMAGE_LINK >>> OK (whitelisted)"
        else
            echo "$IMAGE_LINK >>> OK"
        fi
    fi
    if [ "$HAS_EXCLUDED_FINDINGS" = true ]; then
        echo "OK (whitelisted)" > "$RES_FILE"
    else
        echo "OK" > "$RES_FILE"
    fi
fi

exit 0
