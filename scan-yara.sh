#!/bin/bash
# scan-yara.sh: Malware scanning module for OCI images using YARA
set -Eeuo pipefail

# --- CONFIG ---
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

OUT_DIR="${OUT_DIR:-/tmp}"
# Храним правила в общем кэше (.cache/yara)
CACHE_DIR=$OUT_DIR'/.cache'
YARA_RULES_DIR="$CACHE_DIR/yara"

# Папка с распакованным образом
TARGET_DIR="${UNPACKED_DIR:-$OUT_DIR/image}"
RESULT_FILE="$OUT_DIR/scan-yara.result"
feeds=("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip")
EXP_DAY="6"
IMAGE_LINK=''
LOCAL_FILE=''
OFFLINE_FEEDS=false
OFFLINE_FEEDS_DIR=$OFFLINE_FEEDS_DIR'/yara'

DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yara-feed)
            if [[ -n "$2" && "$2" != --* ]]; then
                feeds+=("$2")
                shift 2
            fi
            ;;
        --yara-exp-day)
            case "$2" in
                "") shift 2 ;;
                *) EXP_DAY=$2 ; shift 2 ;;
            esac ;;
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS=true ; shift 1 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        *)
            # Обработка неизвестных или других флагов
            # echo "Неизвестный параметр: $1"
            shift 1
            ;;
    esac
done

# download and unpack image or use cache
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    /bin/bash $DEBUG$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi

rm -f "$RESULT_FILE"



# --- UPDATE RULES ---
mkdir -p "$YARA_RULES_DIR"
if [[ "$OFFLINE_FEEDS" = true ]] && [[ -d "/opt/db/yara" ]]; then
  YARA_RULES_DIR="/opt/db/yara"
# Check if rules exist and are fresh (less than 6d old)
elif [ -z "$(ls -A "$YARA_RULES_DIR")" ] || [ -n "$(find "$YARA_RULES_DIR" -mtime +$EXP_DAY -print -quit)" ]; then
    echo "Updating YARA rules (to $YARA_RULES_DIR)..."
    for url in "${feeds[@]}"; do
      if [[ "$url" == *.tar.gz || "$url" == *.tgz || "$url" == *.tar ]]; then
        curl -sL "$url" | tar -xzf - -C "$YARA_RULES_DIR"
      elif [[ "$url" == *.zip ]]; then
        tmp_file=$(mktemp)
        if curl -sL "$url" -o "$tmp_file"; then
          unzip -q -o "$tmp_file" -d "$YARA_RULES_DIR"
          rm -f "$tmp_file"
        else
            echo "Error download yara-file on: $url" >&2
        fi
      elif [[ "$url" == *.yara || "$url" == *.yar ]]; then
        curl -sL "$url" -o "$tmp_file"
      else
          echo "Error yara target file format (zip,tar,yara): $url"
      fi
    done
fi


# --- PREPARE RULES FILE ---
COMBINED_FILE=$CACHE_DIR'/yara/combined_rules.yara'
if [[ ! -s "$COMBINED_FILE" ]]; then
  : > "$COMBINED_FILE"
  # Concatenate all .yar files found in cache
  find "$YARA_RULES_DIR" -name "*.yar" -exec cat {} + >> "$COMBINED_FILE"

  # Create dummy rule if empty to prevent syntax error
  if [ ! -s "$COMBINED_FILE" ]; then
    echo "// No rules found" > "$COMBINED_FILE"
  fi
fi



# --- SCAN ---

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Target directory '$TARGET_DIR' not found."
    exit 1
fi

yara -r "$COMBINED_FILE"  "$TARGET_DIR" > "$RESULT_FILE" 2>/dev/null

# Check results
if [ -s "$RESULT_FILE" ]; then
  # Return 1 if malware found
  exit 1
else
  exit 0
fi
