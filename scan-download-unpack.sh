#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

# Usage
#     ./scan-download-unpack.sh [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     -i, --image string                copy image. Example: -i r0binak/cve-2024-21626:v4
#     --tar string                      unpack local tar file. Example: --tar /path/to/private-image.tar

# Examples
# ./scan-download-unpack.sh -i gcr.io/distroless/base-debian11:nonroot-amd64

# To authenticate in the registry, put file auth.json in script directory or run ./scan.sh --auth-path
# See format: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md#format

# Example for user: oauth and password: ABCDEFG
# echo -n 'oauth:ABCDEFG' | base64
#   b2F1dGg6QUJDREVGRw==
# auth.json:
# {
#      "auths": {
#          "cr.yandex": {
#              "auth": "b2F1dGg6QUJDREVGRw=="
#          }
#      }
#  }

set -Eeo pipefail

# exception handling
error_exit()
{
    echo "$1"
    exit 2
}

#var init
IMAGE_LINK=''
LOCAL_FILE=''
DONT_DOWNLOAD=false

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${PISC_OUT_DIR:=/tmp}"
: "${PISC_AUTH_FILE:=$SCRIPTPATH/auth.json}"
# check debug mode to debug child scripts and external tools
DEBUG_SKOPEO='> /dev/null 2>&1'
DEBUG_TAR='2>/dev/null'
if [[ "$-" == *x* ]]; then
    DEBUG_SKOPEO='--debug'
    DEBUG_TAR=''
fi
# silent mode for external tools if not debug
debug_null() {
    if [[ "$-" != *x* ]]; then
        eval &>/dev/null
    fi
}

RES_FILE=$PISC_OUT_DIR'/scan-download-unpack.result'

SKOPEO_AUTH_FLAG=''
if [ -f "$PISC_AUTH_FILE" ]; then
    SKOPEO_AUTH_FLAG="--authfile=$PISC_AUTH_FILE"
fi

# extract options and their arguments into variables.
while [ $# -gt 0 ]; do
    case "$1" in
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

if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
fi

# check cache - last download image
if [ -f $RES_FILE ]; then
    LAST_DOWNLOAD=$(<$RES_FILE)
    if [ "$LAST_DOWNLOAD" == "$IMAGE_LINK" ]; then
        if [ -d "$PISC_OUT_DIR/image" ]; then
            exit 0
        fi
    fi
fi

if [ "$LOCAL_FILE" != "$PISC_OUT_DIR/image.tar" ]; then
    `rm -f $PISC_OUT_DIR/image.tar` debug_null
fi
# copy image to archive
if [ -z "$LOCAL_FILE" ]; then
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> copy\033[0K\r"
    eval "skopeo --tmpdir ${PISC_OUT_DIR} copy docker://$IMAGE_LINK docker-archive:$PISC_OUT_DIR/image.tar $SKOPEO_AUTH_FLAG $DEBUG_SKOPEO" \
        || error_exit "$IMAGE_LINK >>> can't copy, check image name and tag"
fi

echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> unpack image\033[0K\r"
#Sometimes rm and tar occurs an error
#Therefore disable error checking
set +Eeo pipefail
#Unpack to the folder "image"
`rm -rf $PISC_OUT_DIR/image` debug_null
`mkdir $PISC_OUT_DIR/image` debug_null
if [ -z "$LOCAL_FILE" ]; then
    eval tar -xf $PISC_OUT_DIR/image.tar -C $PISC_OUT_DIR/image $DEBUG_TAR
else
    eval tar -xf $LOCAL_FILE -C $PISC_OUT_DIR/image $DEBUG_TAR
fi
#Turning error checking back on
set -Eeo pipefail

# convert docker-save-format to docker-archive-format
if [ ! -z "$LOCAL_FILE" ]; then
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> convert format\033[0K\r"
    if [ -d "$PISC_OUT_DIR/image/blobs/sha256" ]; then
        for f in "$PISC_OUT_DIR/image/blobs/sha256"/*
        do
            MIME_TYPE=(`file --mime-type $f | awk '{print $2}'`)
            filename="${f##*/}"
            if [[ $MIME_TYPE == application/x-tar ]] ; then
                mv $f $PISC_OUT_DIR/image/$filename.tar
            fi
            if [[ $MIME_TYPE == application/json ]] ; then
                mv $f $PISC_OUT_DIR/image/$filename.json
            fi
        done
    fi
fi

echo "$IMAGE_LINK" > $RES_FILE
exit 0
