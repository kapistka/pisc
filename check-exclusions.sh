#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Notes:
# The script checks exclusions listed in the $PISC_EXCLUSIONS_FILE file (whitelist.yaml by default).
# The file format supports YAML syntax. Each exclusion rule applies to the specified image only.
# Ensure that only one exclusion criterion (cve, package, malware, misconfig, days, tag) is used per rule to maintain clarity.
# Optional field expiresOn disables a rule after the specified date in YYYY-MM-DD format.
# Optional field reason stores a free-form text comment and does not affect matching.

# whitelist.yaml file format:

# - image:
#     - "*"
#   cve:
#     - "CVE-2025-1234"
#     - "CVE-2025-5678"
#   reason: "temporary exception for base image update"
#   expiresOn: "2026-03-30"
#
# - misconfig:
#     - "*"
#   image:
#     - "docker.io/php:*"
#
# - malware:                                  # exclude image before virustotal and yara rules
#     - "*"                                   # only * here
#   image:
#     - "docker.io/pulumi/pulumi-python:*"
#
# - tag:
#     - "[0-9]"
#   image:
#     - "debian:*"
#
# - yara:
#     - "Semi-Auto-generated"                 # yara rule substring
#     - "/etc/nginx/owasp-modsecurity-crs/"   # or file path substring
#   image:
#     - "registry.k8s.io/ingress-nginx/controller:*"


# Usage
#     ./check-exclusions.sh -i image_link [ --cve | --package | --malware | --misconfig | --days | --tag  | --yara ]

# Options:
#     -i, --image string                Specify the Docker image to check (use `-i "*"` for local tar archive scan).
#     --cve string                      Check exclusions based on CVE ID.
#     --package string                  Check exclusions based on package name.
#     --malware string                  Check exclusions for yara and virustotal based on a image name.
#     --misconfig string                Check exclusions based on a Dockerfile misconfig
#     --days number                     Check exclusions based on image creation date (number of days for build date).
#     --tag string                      Check exclusions based on image tag.
#     --yara string                     Check exclusions based on yara rules. 

# Examples
# ./check-exclusions.sh -i alpine:latest --cve CVE-2025-12345
# ./check-exclusions.sh -i alpine:latest --package linux-libc-dev
# ./check-exclusions.sh -i alpine:latest --malware "*"
# ./check-exclusions.sh -i alpine:latest --misconfig "*"
# ./check-exclusions.sh -i alpine:latest --days 500
# ./check-exclusions.sh -i alpine:latest --tag latest
# ./check-exclusions.sh -i alpine:latest --yara "Semi-Auto-generated  - file STNC.php.php.txt"
# whitelist.yaml example with expiresOn:
# - package:
#     - "linux-libc-dev"
#   image:
#     - "alpine:latest"
#   reason: "temporary exception for base image update"
#   expiresOn: "2026-03-30"

# Exit Codes:
#     0 - The image does not meet the exclusion criteria
#     1 - The image meets the exclusion criteria
#     2 - Any error

set -Eeo pipefail

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${PISC_OUT_DIR:=/tmp}"
: "${PISC_EXCLUSIONS_FILE:=$SCRIPTPATH/whitelist.yaml}"
ERROR_FILE=$PISC_OUT_DIR'/check-exclusions.error'
CSV_FILE=$PISC_OUT_DIR'/whitelist.csv'
TODAY=$(date '+%Y-%m-%d')

mkdir -p "$PISC_OUT_DIR" 2>/dev/null || {
    printf '   %s\n' "check exclusions: cannot create output dir" >&2
    exit 2
}

# if whitelist not found then exit 0
if [ ! -f "$PISC_EXCLUSIONS_FILE" ]; then
    exit 0
fi

#var init
IMAGE_LINK=''
SEARCH_KEY=''
SEARCH_VALUE=''

error_exit()
{
    printf '   %s' "$1" > "$ERROR_FILE"
    exit 2
}

normalize_iso_date()
{
    local date_value="$1"
    local normalized_date=''

    if normalized_date=$(date -d "$date_value" '+%Y-%m-%d' 2>/dev/null); then
        printf '%s\n' "$normalized_date"
        return 0
    fi

    if normalized_date=$(date -j -f '%Y-%m-%d' "$date_value" '+%Y-%m-%d' 2>/dev/null); then
        printf '%s\n' "$normalized_date"
        return 0
    fi

    return 1
}

is_rule_active()
{
    local expires_on="$1"

    if [ -z "$expires_on" ]; then
        return 0
    fi

    [[ "$expires_on" < "$TODAY" ]] && return 1
    return 0
}

# extract options and their arguments into variables
while [ $# -gt 0 ]; do
    case "$1" in
        --cve|--days|--malware|--misconfig|--package|--tag|--yara)
            if [ -z "${2:-}" ]; then
                error_exit "check exclusions: missing value for $1"
            fi
            SEARCH_KEY=${1:2}
            SEARCH_VALUE=$2
            shift 2
            ;;
        -i|--image)
            if [ -z "${2:-}" ]; then
                error_exit "check exclusions: missing value for $1"
            fi
            IMAGE_LINK=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            error_exit "check exclusions: wrong usage"
            ;;
    esac
done

if [ -z "$IMAGE_LINK" ]; then
    error_exit "check exclusions: set -i argument"
fi
if [ -z "$SEARCH_KEY" ]; then
    error_exit "check exclusions: set cve, package, malware, misconfig, days, tag, yara"
fi
if [ -z "$SEARCH_VALUE" ]; then
    error_exit "check exclusions: set searching value"
fi

# arrays init
declare -a VALUE_LIST
declare -a IMAGE_LIST
declare -a KEY_LIST
declare -a EXPIRES_ON_LIST

# csv cached and removed from parent script
if [ ! -s "$CSV_FILE" ] || [ "$PISC_EXCLUSIONS_FILE" -nt "$CSV_FILE" ]; then
    IMAGE_LIST=()
    KEY_LIST=()
    VALUE_LIST=()
    EXPIRES_ON_LIST=()
    # convert yaml to csv
    yq -o=json '.[]' "$PISC_EXCLUSIONS_FILE" | jq -r '(.expiresOn // "") as $expiresOn | .image[] as $image | to_entries[] | select(.key != "image" and .key != "expiresOn" and .key != "reason") | [($image), .key, .value[], $expiresOn] | @tsv' > "$CSV_FILE" \
      || error_exit "check exclusions: yaml error"
    # read csv
    while IFS=$'\t' read -r image key value expires_on; do
        # check format
        if [ -z "$image" ]; then
            error_exit "check exclusions: wrong format - image should be set"
        fi
        if [ -z "$value" ]; then
            error_exit "check exclusions: wrong format - value should be set"
        fi
        if [[ "$key" == "malware" ]] && [[ "$value" != "*" ]]; then
            error_exit "check exclusions: wrong format - malware should be * only"
        fi
        if [[ "$key" == "misconfig" ]] && [[ "$value" != "*" ]]; then
            error_exit "check exclusions: wrong format - misconfig should be * only"
        fi
        if [ -n "$expires_on" ]; then
            expires_on=$(normalize_iso_date "$expires_on") \
              || error_exit "check exclusions: wrong format - expiresOn should be YYYY-MM-DD"
        fi

        IMAGE_LIST+=("$image")
        KEY_LIST+=("$key")
        VALUE_LIST+=("$value")
        EXPIRES_ON_LIST+=("$expires_on")
    done < "$CSV_FILE"
    : > "$CSV_FILE"
    # write validated cache
    for (( i=0; i<${#IMAGE_LIST[@]}; i++ ));
    do
        printf '%s\t%s\t%s\t%s\n' "${IMAGE_LIST[$i]}" "${KEY_LIST[$i]}" "${VALUE_LIST[$i]}" "${EXPIRES_ON_LIST[$i]}" >> "$CSV_FILE"
    done
fi

# reading from cached csv
IMAGE_LIST=()
VALUE_LIST=()
EXPIRES_ON_LIST=()
while IFS=$'\t' read -r image key value expires_on; do
    # read only SEARCH_KEY needed
    if [[ $SEARCH_KEY == "$key" ]]; then
        IMAGE_LIST+=("$image")
        VALUE_LIST+=("$value")
        EXPIRES_ON_LIST+=("$expires_on")
    fi
done < "$CSV_FILE"

# searching
for (( i=0; i<${#IMAGE_LIST[@]}; i++ ));
do
    if [[ $IMAGE_LINK == "${IMAGE_LIST[$i]}" ]]; then
        if ! is_rule_active "${EXPIRES_ON_LIST[$i]}"; then
            continue
        fi
        if [[ $SEARCH_KEY == "cve" || $SEARCH_KEY == "package" || $SEARCH_KEY == "malware" || $SEARCH_KEY == "misconfig" ]]; then
            # use * pattern
            if [[ $SEARCH_VALUE == "${VALUE_LIST[$i]}" ]]; then
                exit 1
            fi
        elif [[ $SEARCH_KEY == "yara" ]]; then
            # search substring: yara rule or file path
            if [[ "$SEARCH_VALUE" == *"${VALUE_LIST[$i]}"* ]]; then
                exit 1
            fi
        elif [[ $SEARCH_KEY == "tag" ]]; then
            # use [0-9] pattern
            if [[ "$SEARCH_VALUE" =~ ${VALUE_LIST[$i]} ]]; then
                exit 1
            fi
        elif [[ $SEARCH_KEY == "days" ]]; then
            if [[ $SEARCH_VALUE =~ ^[0-9]+(\.[0-9]+)?$ && ${VALUE_LIST[$i]} =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                if awk "BEGIN {exit !($SEARCH_VALUE <= ${VALUE_LIST[$i]})}"; then
                    exit 1
                fi
            else
                error_exit "check exclusions: wrong format - days should be a number"
            fi
        fi
    fi
done

exit 0
