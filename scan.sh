#!/bin/bash
# Public OCI-Image Security Checker
# Author: @kapistka, 2026

set -Eeo pipefail

VERSION='v0.19.0'

usage() {
    cat <<EOF

Public OCI-Image Security Checker
https://github.com/kapistka/pisc
Author: @kapistka, 2026

                    ##         .
              ## ## ##        ==
           ## ## #P WN       ===
       /""""""""""""""""\___/ ===
      {        /              /
       \______ o          __/
         |||||\        __/
          |||||\______/

A command-line tool to assess the security of OCI container images.
Exits with code '1' if any of the following conditions are met:
  - The image contains malware.
  - The image has exploitable vulnerabilities.
  - The image has dangerous build misconfigurations.
  - The image is older than a specified number of days.
  - The image uses a non-versioned tag (e.g., ':latest').

Usage:
  $(basename "${BASH_SOURCE[0]}") [flags] [-i IMAGE | -f FILE | --tar TARFILE]

Flags:
  --auth-file <string>            Path to the auth file (see 'scan-download-unpack.sh#L14')
  -d, --date                      Check image age against threshold (default: 365 days).
  --d-days <int>                  Custom threshold for build date check (in days). Example: '--d-days 180'.
  -e, --exploits                  Check for vulnerabilities with known exploits (using Trivy + Grype + inthewild.io + empiricalsecurity.com).
  --epss-and                      Use AND logic to combine EPSS score and exploit presence. If disabled, OR logic is applied (default: OR).
  --epss-min <float>              Minimum EPSS score threshold used for filtering vulnerabilities (default: 0.5).
  --exclusions-file <string>      Path to the exclusions file (see 'check-exclusion.sh#L5')
  -f, --file <string>             Batch scan images from file. Example: '-f /path/to/images.txt'.
  -h, --help                      Display this help message.
  --ignore-errors                 Ignore errors from external tools and continue execution.
  -i, --image <string>            Single image to scan. Example: '-i r0binak/mtkpi:v1.4'.
  -l, --latest                    Detect non-versioned tags (e.g., ':latest').
  -m, --misconfig                 Scan for dangerous build misconfigurations.
  --offline-feeds                 Use a self-contained offline image with pre-downloaded vulnerability feeds (e.g., :latest-feeds).
  --output-dir <string>           Output tmp and results file directory. Default /tmp. Example: '--output-dir /tmp'
  --scanner [trivy|grype|all]     Choose which scanner to use: Trivy, Grype, or both (default: all)
  --severity-min <string>         Minimal severity of vulnerabilities [UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL] default [HIGH]
  --show-exploits                 Show exploit details
  --tar <string>                  Scan local TAR archive of image layers. Example: '--tar /path/to/private-image.tar'.
  --trivy-server <string>         Trivy server endpoint URL. Example: '--trivy-server http://trivy.something.io:8080'.
  --trivy-token <string>          Authentication token for Trivy server. Example: '--trivy-token 0123456789abZ'.
  -v, --version                   Display version.
  --virustotal-key <string>       VirusTotal API key for malware scanning. Example: '--virustotal-key 0123456789abcdef'.
  --vulners-key <string>          Vulners.com API key (alternative to inthewild.io). Example: '--vulners-key 0123456789ABCDXYZ'.
  -y, --yara                      Scanning with YARA rules for malware
  --yara-file <string>            Path to additional YARA rules. Example: '--yara-file /path/to/custom-rules.yar'.

Examples:
  ./scan.sh --virustotal-key 0123456789abcdef --yara -i r0binak/mtkpi:v1.3
  ./scan.sh -delmy -i kapistka/log4shell:0.0.3-nonroot --virustotal-key 0123456789abcdef
  ./scan.sh -delmy --trivy-server http://trivy.something.io:8080 --trivy-token 0123abZ --virustotal-key 0123456789abcdef -f images.txt
EOF
}

# var init
CHECK_DATE=false
CHECK_EXPLOITS=false
CHECK_LATEST=false
CHECK_MISCONFIG=false
CHECK_YARA=false
DEFAULT_OFFLINE_CACHE='/opt/db'
EPSS_AND_FLAG=''
EPSS_MIN='0.5'
FLAG_IMAGE='-i'
IGNORE_ERRORS_FLAG=''
IMAGE_LINK=''
LOCAL_FILE=''
OFFLINE_FEEDS_FLAG=''
OLD_BUILD_DAYS=365
SCAN_RETURN_CODE=0
SCANNER='all'
SEVERITY='HIGH'
SHOW_EXPLOITS_FLAG=''
TRIVY_SERVER=''
TRIVY_TOKEN=''
VIRUSTOTAL_API_KEY=''
VULNERS_API_KEY=''
FILE_SCAN=''
IS_LIST_IMAGES=false

FEEDS_DATE_EPSS=''
FEEDS_DATE_EXPLOITS=''
FEEDS_DATE_GRYPE=''
FEEDS_DATE_TRIVY=''
FEEDS_DATE_YARA=''

# vars to export
PISC_AUTH_FILE=''
PISC_EXCLUSIONS_FILE=''
PISC_OUT_DIR='/tmp'
PISC_FEEDS_DIR=$PISC_OUT_DIR'/.cache'
PISC_YARA_CUSTOM_FILE=''

C_BLU='\033[1;34m'
C_GRN='\033[1;32m'
C_YLW='\033[0;33m'
C_NIL='\033[0m'
C_RED='\033[0;31m'
EMOJI_ON='\U2795'      # plus
EMOJI_OFF='\U2796'     # minus
EMOJI_OK='\U1F44D'     # thumbs up
EMOJI_NOT_OK='\U1F648' # see-no-evil monkey
EMOJI_LATEST='\U2693'  # anchor
EMOJI_OLD='\U1F4C6'    # tear-off calendar
EMOJI_TAR='\U1F4E6'    # package
EMOJI_LIST='\U1F4C3'   # page with curl
EMOJI_DOCKER='\U1F433' # whale

U_LINE2='\U02550\U02550\U02550\U02550\U02550\U02550\U02550\U02550\U02550'
U_LINE=$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2$U_LINE2

# it is important for run *.sh by ci-runner
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# check debug mode to debug child scripts and external tools
DEBUG=''
if [[ "$-" == *x* ]]; then
    DEBUG='-x '
fi
# turn on/off debugging for hide sensetive data
debug_set() {
    if [ "$1" = false ] ; then
        set +x
    else
        if [ "$DEBUG" != "" ]; then
            set -x
        fi
    fi
}

exit_unset()
{
    unset PISC_AUTH_FILE
    unset PISC_YARA_CUSTOM_FILE
    unset PISC_EXCLUSIONS_FILE
    unset PISC_FEEDS_DIR
    unset PISC_OUT_DIR
    exit $1
}

print_version() {
    echo $VERSION
}

# read the options
debug_set false
ARGS=$(getopt -o dehf:i:lmvy --long auth-file:,date,d-days:,epss-and,epss-min:,exclusions-file:,exploits,file:,help,ignore-errors,image:,latest,misconfig,offline-feeds,output-dir:,scanner:,severity-min:,show-exploits,tar:,trivy-server:,trivy-token:,version,virustotal-key:,vulners-key:,yara,yara-file: -n $0 -- "$@")
eval set -- "$ARGS"
debug_set true

# options to vars.
while true ; do
    case "$1" in
        --auth-file)
            case "$2" in
                "") shift 2 ;;
                *) PISC_AUTH_FILE=$2 ; shift 2 ;;
            esac ;;
        -d|--date)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_DATE=true ; shift 1 ;;
            esac ;;
        --d-days)
            case "$2" in
                "") shift 2 ;;
                *) CHECK_DATE=true ; OLD_BUILD_DAYS=$2 ; shift 2 ;;
            esac ;;
        -e|--exploits)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_EXPLOITS=true ; shift 1 ;;
            esac ;;
        --epss-and)
            case "$2" in
                "") shift 1 ;;
                *) EPSS_AND_FLAG="--epss-and" ; shift 1 ;;
            esac ;;
        --epss-min)
            case "$2" in
                "") shift 2 ;;
                *) EPSS_MIN=$2 ; shift 2 ;;
            esac ;;
        --exclusions-file)
            case "$2" in
                "") shift 2 ;;
                *) PISC_EXCLUSIONS_FILE=$2 ; shift 2 ;;
            esac ;;
        -f|--file)
            case "$2" in
                "") shift 2 ;;
                *) FILE_SCAN=$2 ; CHECK_LOCAL=false ; shift 2 ;;
            esac ;;
        -h|--help) usage ; exit_unset 0;;
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) IGNORE_ERRORS_FLAG='--ignore-errors' ; shift 1 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; CHECK_LOCAL=false ; shift 2 ;;
            esac ;;
        -l|--latest )
            case "$2" in
                "") shift 1 ;;
                *) CHECK_LATEST=true ; shift 1 ;;
            esac ;;
        -m|--misconfig)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_MISCONFIG=true ; shift 1 ;;
            esac ;;
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS_FLAG='--offline-feeds' ; shift 1 ;;
            esac ;;
        --output-dir)
            case "$2" in
                "") shift 2 ;;
                *) PISC_OUT_DIR=$2 ; shift 2 ;;
            esac ;;
        --scanner)
            case "$2" in
                "") shift 2 ;;
                *) SCANNER=$2 ; shift 2 ;;
            esac ;;
        --severity-min)
            case "$2" in
                "") shift 2 ;;
                *) SEVERITY=$2 ; shift 2 ;;
            esac ;;
        --show-exploits)
            case "$2" in
                "") shift 1 ;;
                *) SHOW_EXPLOITS_FLAG='--show-exploits' ; shift 1 ;;
            esac ;;
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;
        --trivy-server)
            case "$2" in
                "") shift 2 ;;
                *) TRIVY_SERVER=$2 ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;
        --trivy-token)
            case "$2" in
                "") shift 2 ;;
                *)  debug_set false ; TRIVY_TOKEN=$2 ; debug_set true ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;
        -v|--version) print_version ; exit_unset 0;;
        --virustotal-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; VIRUSTOTAL_API_KEY=$2 ; debug_set true ; shift 2 ;;
            esac ;;
        --vulners-key)
            case "$2" in
                "") shift 2 ;;
                *) debug_set false ; VULNERS_API_KEY=$2 ; debug_set true ; CHECK_EXPLOITS=true ; shift 2 ;;
            esac ;;
        -y|--yara)
            case "$2" in
                "") shift 1 ;;
                *) CHECK_YARA=true ; shift 1 ;;
            esac ;;
        --yara-file)
            case "$2" in
                "") shift 2 ;;
                *) CHECK_YARA=true ; PISC_YARA_CUSTOM_FILE=$2 ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit_unset 2 ;;
    esac
done

# remove exclusions-cache-csv, exploits-info
eval "rm -f $PISC_OUT_DIR/whitelist.csv $PISC_OUT_DIR/*.expl"

# arguments check
if [ ! -z "$FILE_SCAN" ]; then
    if [ -f $PISC_OUT_DIR'/'$FILE_SCAN ]; then
        FILE_SCAN=$PISC_OUT_DIR'/'$FILE_SCAN
    elif [ -f $SCRIPTPATH'/'$FILE_SCAN ]; then
        FILE_SCAN=$SCRIPTPATH'/'$FILE_SCAN
    fi
    if [ ! -f $FILE_SCAN ]; then
        echo "$FILE_SCAN >>> File -f not found. Try '$0 --help' for more information."
        exit_unset 2
    else
        IS_LIST_IMAGES=true
        LIST_IMAGES=()
        LIST_IMAGES=(`awk '{print $1}' $FILE_SCAN`)
    fi
elif [ ! -z "$LOCAL_FILE" ]; then
    if [ -f $PISC_OUT_DIR'/'$LOCAL_FILE ]; then
        LOCAL_FILE=$PISC_OUT_DIR'/'$LOCAL_FILE
    elif [ -f $SCRIPTPATH'/'$LOCAL_FILE ]; then
        LOCAL_FILE=$SCRIPTPATH'/'$LOCAL_FILE
    fi
    if [ ! -f $LOCAL_FILE ]; then
        echo "$LOCAL_FILE >>> File --tar not found. Try '$0 --help' for more information."
        exit_unset 2
    else
        # disable check latest tag for local-tar
        CHECK_LATEST=false
        FLAG_IMAGE='--tar'
    fi
else
    if [ -z "$IMAGE_LINK" ]; then
        echo "Please specify image or file -f. Try '$0 --help' for more information."
        exit_unset 2
    fi
fi
# PISC_OUT_DIR - write access
if mkdir -p "$PISC_OUT_DIR" 2>/dev/null && [[ -w "$PISC_OUT_DIR" ]]; then
    export PISC_OUT_DIR
else
    echo "Output dir >>> No access to write $PISC_OUT_DIR. Try '$0 --help' for more information."
    exit_unset 2
fi
# OFFLINE_FEEDS_FLAG and DB size
check_db() {
    if [ "$NO_FEEDS" = false ]; then
        local F="$1"
        local MIN="$2"
        if [[ ! -f "$F" ]]; then
            NO_FEEDS=true
        else
            if (( $(stat -c %s -- "$F" 2>/dev/null) < MIN )); then
                NO_FEEDS=true
            fi
        fi
    fi
}
check_db_all() {
    if [ "$CHECK_EXPLOITS" = true ]; then
        check_db "$PISC_FEEDS_DIR/trivy/db/trivy.db"            900000000
        check_db "$PISC_FEEDS_DIR/trivy/java-db/trivy-java.db" 1300000000
        check_db "$PISC_FEEDS_DIR/grype/6/vulnerability.db"    1000000000
        check_db "$PISC_FEEDS_DIR/epss.csv"                       9000000
        check_db "$PISC_FEEDS_DIR/inthewild.db"                 148000000
    fi
    if [ "$CHECK_YARA" = true ]; then
        check_db "$PISC_FEEDS_DIR/yara/rules.yar"                17000000
        check_db "$PISC_FEEDS_DIR/yara/rules.yar.comp"           38000000
    fi 
}
NO_FEEDS=false
if [ ! -z "$OFFLINE_FEEDS_FLAG" ]; then
    PISC_FEEDS_DIR=$DEFAULT_OFFLINE_CACHE
    check_db_all
    if [ "$NO_FEEDS" = true ]; then
        NO_FEEDS=false
        PISC_FEEDS_DIR=$PISC_OUT_DIR'/.cache'
        check_db_all
    fi
    if [ "$NO_FEEDS" = true ]; then
        echo "No feeds >>> $OFFLINE_FEEDS_FLAG set, but no feeds in $PISC_FEEDS_DIR. Use image with tag :$VERSION-feeds"
        exit_unset 2    
    fi
fi
export PISC_FEEDS_DIR
# trivy dirty hack to resolv read-only DB https://github.com/aquasecurity/trivy/issues/3041
if [ -f $PISC_FEEDS_DIR'/trivy/fanal/fanal.db.tmp' ]; then
    mkdir -p /tmp/.cache/trivy/fanal/
    cp $PISC_FEEDS_DIR'/trivy/fanal/fanal.db.tmp' '/tmp/.cache/trivy/fanal/fanal.db'
    chmod +w '/tmp/.cache/trivy/fanal/fanal.db'
fi
# PISC_AUTH_FILE
if [ ! -z "$PISC_AUTH_FILE" ]; then
    if [ -f $PISC_OUT_DIR'/'$PISC_AUTH_FILE ]; then
        PISC_AUTH_FILE=$PISC_OUT_DIR'/'$PISC_AUTH_FILE
    elif [ -f $SCRIPTPATH'/'$PISC_AUTH_FILE ]; then
        PISC_AUTH_FILE=$SCRIPTPATH'/'$PISC_AUTH_FILE
    fi
    if [ ! -f $PISC_AUTH_FILE ]; then
        echo "$PISC_AUTH_FILE >>> Auth file not found. Try '$0 --help' for more information."
        exit_unset 2
    else
        export PISC_AUTH_FILE
    fi
fi
# PISC_EXCLUSIONS_FILE
if [ ! -z "$PISC_EXCLUSIONS_FILE" ]; then
    if [ -f $PISC_OUT_DIR'/'$PISC_EXCLUSIONS_FILE ]; then
        PISC_EXCLUSIONS_FILE=$PISC_OUT_DIR'/'$PISC_EXCLUSIONS_FILE
    elif [ -f $SCRIPTPATH'/'$PISC_EXCLUSIONS_FILE ]; then
        PISC_EXCLUSIONS_FILE=$SCRIPTPATH'/'$PISC_EXCLUSIONS_FILE
    fi
    if [ ! -f $PISC_EXCLUSIONS_FILE ]; then
        echo "$PISC_EXCLUSIONS_FILE >>> Exclusions file not found. Try '$0 --help' for more information."
        exit_unset 2
    else
        export PISC_EXCLUSIONS_FILE
    fi
fi
# PISC_YARA_CUSTOM_FILE
if [ ! -z "$PISC_YARA_CUSTOM_FILE" ]; then
    if [ -f $PISC_OUT_DIR'/'$PISC_YARA_CUSTOM_FILE ]; then
        PISC_YARA_CUSTOM_FILE=$PISC_OUT_DIR'/'$PISC_YARA_CUSTOM_FILE
    elif [ -f $SCRIPTPATH'/'$PISC_YARA_CUSTOM_FILE ]; then
        PISC_YARA_CUSTOM_FILE=$SCRIPTPATH'/'$PISC_YARA_CUSTOM_FILE
    fi
    if [ ! -f $PISC_YARA_CUSTOM_FILE ]; then
        echo "$PISC_YARA_CUSTOM_FILE >>> YARA custom file not found. Try '$0 --help' for more information."
        exit_unset 2
    else
        export PISC_YARA_CUSTOM_FILE
    fi
fi
# SCANNERS
if [[ "$SCANNER" != "trivy" && "$SCANNER" != "grype" && "$SCANNER" != "all" ]]; then
    echo "Invalid --scanner value: $SCANNER. Must be one of: trivy, grype, all. Try '$0 --help' for more information."
    exit_unset 2
fi
if ! [[ "$EPSS_MIN" =~ ^0\.[0-9]+$ ]]; then
    echo "Invalid --epss-min value: $EPSS_MIN. Must be a float between 0 and 1 (exclusive). Try '$0 --help' for more information."
    exit_unset 2
fi
# debug exclusions - sensitive data
debug_set false
if [ -z "$TRIVY_SERVER" ] && [ ! -z "$TRIVY_TOKEN" ]; then
    echo "Trivy URL was specified but trivy token not. Try '$0 --help' for more information."
    exit_unset 2
fi
if [ ! -z "$TRIVY_SERVER" ] && [ -z "$TRIVY_TOKEN" ]; then
    echo "Trivy token was specified but trivy URL not. Try '$0 --help' for more information."
    exit_unset 2
fi
if [ "$CHECK_EXPLOITS" = false ] && [ "$CHECK_DATE" = false ] &&  [ "$CHECK_LATEST" = false ] && [ "$CHECK_MISCONFIG" = false ] && [ -z "$VIRUSTOTAL_API_KEY" ] && [ "$CHECK_YARA" = false ]; then
    echo "No checks selected. Try '$0 --help' for more information."
    exit_unset 2
fi
debug_set true

# check tools exist
IS_TOOLS_NOT_EXIST=false
TOOLS_NOT_EXIST_STR=''
LIST_TOOLS=(awk column curl file find jq sha256sum skopeo sqlite3 tar tr trivy yq zcat grype yara yarac unzip)
for (( i=0; i<${#LIST_TOOLS[@]}; i++ ));
do
    if ! command -v ${LIST_TOOLS[$i]} &> /dev/null
    then
        IS_TOOLS_NOT_EXIST=true
        TOOLS_NOT_EXIST_STR=$TOOLS_NOT_EXIST_STR$'\n  '${LIST_TOOLS[$i]}
    fi
done
if [ "$IS_TOOLS_NOT_EXIST" = true ] ; then
    echo "First you need to install these tools:$TOOLS_NOT_EXIST_STR"
    exit_unset 3
fi

# check GNU-version of tar
if ! `tar --version | grep -q "GNU"`; then
    echo "You need to install GNU-version of tar"
    exit_unset 3
fi

# get feeds dates
P=''
if [ -z "$OFFLINE_FEEDS_FLAG" ]; then
    P=' +'
fi
if [ "$CHECK_EXPLOITS" = true ]; then
    if [ -f $PISC_FEEDS_DIR'/grype/6/import.json' ]; then
        FEEDS_DATE_GRYPE="            "$(jq -r '.source | capture("_(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2})T").d' $PISC_FEEDS_DIR/grype/6/import.json)"$P"
    fi
    if [ -f $PISC_FEEDS_DIR'/trivy/db/metadata.json' ]; then
        FEEDS_DATE_TRIVY="            "$(jq -r '.UpdatedAt[0:10]' $PISC_FEEDS_DIR/trivy/db/metadata.json)"$P"
    fi
    if [ -f $PISC_FEEDS_DIR'/epss.csv' ]; then
        FEEDS_DATE_EPSS="             "$(sed -n 's/.*score_date:\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\)T.*/\1/p' $PISC_FEEDS_DIR/epss.csv)"$P"
    fi
    if [ -f $PISC_FEEDS_DIR/'inthewild.db' ]; then
        FEEDS_DATE_EXPLOITS="         "$(sqlite3 -column "file:$PISC_FEEDS_DIR/inthewild.db?mode=ro&immutable=1" "SELECT MAX("timeStamp")FROM exploits;" | cut -dT -f1)"$P"
    fi
fi    
if [ "$CHECK_YARA" = true ]; then
    if [ -f $PISC_FEEDS_DIR'/yara/rules.yar' ]; then
        FEEDS_DATE_YARA="             "$(sed -n 's/^ \* Creation Date:[[:space:]]*\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\).*/\1/p' $PISC_FEEDS_DIR/yara/rules.yar | head -n1)"$P"
    fi
fi

# show enable/disable options
echo -e "$U_LINE"
if [ ! -z "$LOCAL_FILE" ]; then
    echo -e "$EMOJI_TAR local file: $LOCAL_FILE"
elif [ "$IS_LIST_IMAGES" = true ]; then
    echo -e "$EMOJI_LIST images from list: $FILE_SCAN"
elif [ ! -z "$IMAGE_LINK" ]; then
    echo -e "$EMOJI_DOCKER image: $IMAGE_LINK"
fi
EMOJI_OPT=$EMOJI_OFF
SCANNER_MSG=''
if [ "$CHECK_YARA" = true ]; then
    if [ -z "$PISC_YARA_CUSTOM_FILE" ]; then
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON yara $FEEDS_DATE_YARA"
    else
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON yara $FEEDS_DATE_YARA (+ custom rules)"
    fi
    EMOJI_OPT=$EMOJI_ON
else
    SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_OFF yara"   
fi
debug_set false
if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
    SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON virustotal.com"
    EMOJI_OPT=$EMOJI_ON
else 
    SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_OFF virustotal.com"
fi
debug_set true
if [ "$EMOJI_OPT" == "$EMOJI_ON" ] ; then
    echo -e "   $EMOJI_ON Malware scanning$SCANNER_MSG"
else
    echo -e "   $EMOJI_OFF Malware scanning"
fi

EMOJI_OPT=$EMOJI_OFF
SCANNER_MSG=''
if [ "$CHECK_EXPLOITS" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
    if [ "$SCANNER" == "trivy" ] || [ "$SCANNER" == "all" ] ; then
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON Trivy $FEEDS_DATE_TRIVY"
    else
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_OFF Trivy"
    fi    
    if [ "$SCANNER" == "grype" ] || [ "$SCANNER" == "all" ] ; then
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON Grype $FEEDS_DATE_GRYPE"
    else
        SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_OFF Grype"
    fi    
    SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON EPSS $FEEDS_DATE_EPSS"
    SCANNER_MSG=$SCANNER_MSG$'\n '"      $EMOJI_ON Exploits $FEEDS_DATE_EXPLOITS"
    if [ -z "$OFFLINE_FEEDS_FLAG" ]; then
        SCANNER_MSG=$SCANNER_MSG$'\n '"       feeds: online"
    else
        SCANNER_MSG=$SCANNER_MSG$'\n '"       feeds: offline"
    fi
    SCANNER_MSG=$SCANNER_MSG$'\n '"       exploit filter: EPSS > $EPSS_MIN"
    if [ "$EPSS_AND_FLAG" = "" ] ; then
        SCANNER_MSG=$SCANNER_MSG" OR known exploits"
    else
        SCANNER_MSG=$SCANNER_MSG" AND known exploits"
    fi
    SCANNER_MSG=$SCANNER_MSG$'\n '"       severity filter: $SEVERITY"
fi
echo -e "   $EMOJI_OPT Vulnerability scanning$SCANNER_MSG"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_MISCONFIG" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT Build configuration scanning"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_DATE" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT Check if image is older than $OLD_BUILD_DAYS days"
EMOJI_OPT=$EMOJI_OFF
if [ "$CHECK_LATEST" = true ] ; then
    EMOJI_OPT=$EMOJI_ON
fi
echo -e "   $EMOJI_OPT Check for non-versioned tags (e.g., :latest)"

# single image scan
scan_image() {
    eval "rm -f $PISC_OUT_DIR/*.error"

    CREATED_DATE='1970-01-01'
    CREATED_DATE_LAST='1970-01-01'
    IS_EXCLUDED=false
    IS_EXPLOITABLE=false
    IS_HIGH_EPSS=false
    IS_LATEST=false
    IS_MISCONFIG=false
    IS_OLD=false
    IS_MALWARE_VT=false
    IS_MALWARE_YARA=false
    EXCLUDED_STR=''
    LIST_ERRORS=()

    # redefine image link (function execute from file-list too)
    IMAGE_LINK=$1
    echo -e "$U_LINE"

    # non-version tag checking (evolution of "latest")
    if [ "$CHECK_LATEST" = true ]; then
        echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> check non version tag\033[0K\r"
        # exclude digest
        if [[ $IMAGE_LINK != *"@"* ]]; then
            IMAGE_TAG=${IMAGE_LINK#*:}
            if [[ ! $IMAGE_TAG =~ [0-9]*[0-9]\.[0-9]*[0-9] ]]; then
                # check exclusions
                set +e
                /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --tag $IMAGE_TAG
                if [[ $? -eq 1 ]] ; then
                    IS_EXCLUDED=true
                    EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   tag whitelisted"
                else
                    IS_LATEST=true
                fi
                set -e
            fi
        fi
    fi

    # misconfigurations scanning
    if [ "$CHECK_MISCONFIG" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-misconfig.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK
        MISCONFIG_RESULT_MESSAGE=$(<$PISC_OUT_DIR/scan-misconfig.result)
        if [ "$MISCONFIG_RESULT_MESSAGE" != "OK" ] && [ "$MISCONFIG_RESULT_MESSAGE" != "OK (whitelisted)" ]; then
            IS_MISCONFIG=true
        elif [ "$MISCONFIG_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   misconfig whitelisted"
        fi
    fi

    # yara scanning
    if [ "$CHECK_YARA" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-yara.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK $IGNORE_ERRORS_FLAG $OFFLINE_FEEDS_FLAG
        YARA_RESULT_MESSAGE=$(<$PISC_OUT_DIR/scan-yara.result)
        if [ "$YARA_RESULT_MESSAGE" != "OK" ] && [ "$YARA_RESULT_MESSAGE" != "OK (whitelisted)" ]; then
            IS_MALWARE_YARA=true
        elif [ "$YARA_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   malware (yara) whitelisted"
        fi
    fi

    # virustotal scanning
    debug_set false
    if [ ! -z "$VIRUSTOTAL_API_KEY" ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-virustotal.sh --dont-output-result --virustotal-key $VIRUSTOTAL_API_KEY $FLAG_IMAGE $IMAGE_LINK $IGNORE_ERRORS_FLAG
        VIRUSTOTAL_RESULT_MESSAGE=$(<$PISC_OUT_DIR/scan-virustotal.result)
        if [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK" ] && [ "$VIRUSTOTAL_RESULT_MESSAGE" != "OK (whitelisted)" ]; then
            IS_MALWARE_VT=true
        elif [ "$VIRUSTOTAL_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   malware (virustotal) whitelisted"
        fi
    fi
    debug_set true

    # exploitable vulnerabilities scanning
    if [ "$CHECK_EXPLOITS" = true ]; then
        debug_set false
        PARAMS=" --scanner $SCANNER $OFFLINE_FEEDS_FLAG"
        if [ ! -z "$VULNERS_API_KEY" ]; then
            PARAMS=$PARAMS" --vulners-key $VULNERS_API_KEY"
        fi
        if [ ! -z "$TRIVY_SERVER" ]; then
            PARAMS=$PARAMS" --trivy-server $TRIVY_SERVER --trivy-token $TRIVY_TOKEN"
        fi
        /bin/bash $DEBUG$SCRIPTPATH/scan-vulnerabilities.sh --severity-min $SEVERITY $SHOW_EXPLOITS_FLAG $EPSS_AND_FLAG --epss-min $EPSS_MIN --dont-output-result $FLAG_IMAGE $IMAGE_LINK $PARAMS $IGNORE_ERRORS_FLAG
        debug_set true
        VULNERABILITIES_RESULT_MESSAGE=$(<$PISC_OUT_DIR/scan-vulnerabilities.result)
        if [ "$VULNERABILITIES_RESULT_MESSAGE" != "OK" ] && [ "$VULNERABILITIES_RESULT_MESSAGE" != "OK (whitelisted)" ] ; then
            IS_EXPLOITABLE=true
            # force check date if it exploitable
            CHECK_DATE=true
        elif [ "$VULNERABILITIES_RESULT_MESSAGE" == "OK (whitelisted)" ] ; then
            IS_EXCLUDED=true
            EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   exploitable vulnerabilities whitelisted"
        fi
    fi

    debug_set true
    # old build date checking
    # after exploits checking - force CHECK_DATE = true
    if [ "$CHECK_DATE" = true ]; then
        /bin/bash $DEBUG$SCRIPTPATH/scan-date.sh --dont-output-result $FLAG_IMAGE $IMAGE_LINK
        CREATED_DATE=$(<$PISC_OUT_DIR/scan-date.result)
        CREATED_DATE_LAST=$CREATED_DATE
        # was built more than N days ago
        if [ "$CREATED_DATE" != "0001-01-01" ] && [ "$CREATED_DATE" != "1970-01-01" ]; then
            AGE_DAYS=$(( ($(date +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
            # check exclusions
            set +e
            /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --days $AGE_DAYS
            if [[ $? -eq 1 ]] ; then
                IS_EXCLUDED=true
                EXCLUDED_STR="${EXCLUDED_STR:+$EXCLUDED_STR$'\n'}   date whitelisted"
            else
                if awk "BEGIN {exit !($AGE_DAYS >= $OLD_BUILD_DAYS)}"; then
                    IS_OLD=true
                fi
            fi
            set -e
        fi
    fi

    # candidates for a new image if it is outdated or there are exploits
    if [ -z "$LOCAL_FILE" ]; then
        if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ]; then
            /bin/bash $DEBUG$SCRIPTPATH/scan-new-tags.sh --dont-output-result -i $IMAGE_LINK
            CREATED_DATE_LAST=`awk 'NR==1 {print; exit}' $PISC_OUT_DIR/scan-new-tags.result`
            NEW_TAGS_RESULT_MESSAGE=`awk 'NR>1 {print}' $PISC_OUT_DIR/scan-new-tags.result`
        fi
    fi

    # result output
    # separating strip for CI
    echo -ne "$U_LINE\033[0K\r"
    # output of the result by the non-version tag
    if [ "$IS_LATEST" = true ]; then
        echo -e "$EMOJI_LATEST $C_RED$IMAGE_LINK$C_NIL >>> non-version tag                              "
    fi
    # echo misconfig result
    if [ "$IS_MISCONFIG" = true ]; then
        echo -e "$MISCONFIG_RESULT_MESSAGE"
    fi
    # echo virustotal result
    if [ "$IS_MALWARE_YARA" = true ]; then
        echo -e "$YARA_RESULT_MESSAGE"
    fi
    # echo virustotal result
    if [ "$IS_MALWARE_VT" = true ]; then
        echo -e "$VIRUSTOTAL_RESULT_MESSAGE"
    fi
    # echo vulnerabilities + exploit result
    if [ "$IS_EXPLOITABLE" = true ]; then
        echo -e "$VULNERABILITIES_RESULT_MESSAGE"
    fi
    # additional output of newest date and newest tags
    if [ "$IS_OLD" = true ] || [ "$IS_EXPLOITABLE" = true ] ; then
        DIFF_DAYS=$(( ($(date -d $CREATED_DATE_LAST +%s) - $(date -d $CREATED_DATE +%s)) / 86400 ))
        if (( $DIFF_DAYS > 0 )); then
            echo -e "$EMOJI_OLD $C_RED$IMAGE_LINK$C_NIL >>> created: $CREATED_DATE. Last update: $CREATED_DATE_LAST"
            echo -e "$NEW_TAGS_RESULT_MESSAGE"
        else
            echo -e "$EMOJI_OLD $C_RED$IMAGE_LINK$C_NIL >>> created: $CREATED_DATE. Find another image"
        fi
    fi

    # show ignored errors
    set +Eeo pipefail
    LIST_ERRORS=($(find "$PISC_OUT_DIR" -name '*.error' -type f 2>/dev/null))
    set -Eeo pipefail
    set -e
    if (( ${#LIST_ERRORS[@]} > 0 )); then
        STR_ERRORS=''
        for (( i=0; i<${#LIST_ERRORS[@]}; i++ ));
        do
            STR_ERRORS+=$(<"${LIST_ERRORS[$i]}")$'\n'
        done
        STR_ERRORS="${STR_ERRORS%$'\n'*}"
    fi

    # decision logic
    if [ "$IS_OLD" = true ] ||  [ "$IS_EXPLOITABLE" = true ] ||  [ "$IS_MALWARE_YARA" = true ] ||  [ "$IS_MALWARE_VT" = true ] ||  [ "$IS_LATEST" = true ] || [ "$IS_MISCONFIG" = true ]; then
        SCAN_RETURN_CODE=1
        # show ignored errors
        if (( ${#LIST_ERRORS[@]} > 0 )); then
            echo -e "$EMOJI_NOT_OK $C_YLW$IMAGE_LINK$C_NIL >>> ignored errors:                              "
            echo -e "$STR_ERRORS"
        fi
        # show whitelisted reason
        if [ ! -z "$EXCLUDED_STR" ]; then
            echo -e "$EXCLUDED_STR"
        fi
    else
        if (( ${#LIST_ERRORS[@]} > 0 )) || [ "$IS_EXCLUDED" = true ]; then
            echo -e "$EMOJI_NOT_OK $C_YLW$IMAGE_LINK$C_NIL >>> OK, but                                         "
            if [ ! -z "$EXCLUDED_STR" ]; then
                echo -e "$EXCLUDED_STR"
            fi
            if (( ${#LIST_ERRORS[@]} > 0 )); then
                echo -e "$STR_ERRORS"
            fi
        else
            echo -e "$EMOJI_OK $C_GRN$IMAGE_LINK$C_NIL >>> OK                                      "
        fi
    fi
}

# scan local-tar
if [ ! -z "$LOCAL_FILE" ]; then
    scan_image "$LOCAL_FILE"
# scan list from file
elif [ "$IS_LIST_IMAGES" = true ]; then
    for (( j=0; j<${#LIST_IMAGES[@]}; j++ ));
    do
        scan_image "${LIST_IMAGES[j]}"
    done
# scan image from argument
else
    scan_image "$IMAGE_LINK"
fi

exit_unset $SCAN_RETURN_CODE
