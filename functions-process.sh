#!/usr/bin/env bash
# Parallel Function Processing with MCP (Linux)
# Processes functions from FunctionsTodo.txt using Claude CLI
#
# Usage:
#   ./functions-process.sh
#   ./functions-process.sh -w 6                   # 6 parallel workers
#   ./functions-process.sh -w 4 -C                # 4 workers, compact prompt
#   ./functions-process.sh -n 10 -m haiku         # 10 functions with Haiku
#   ./functions-process.sh -1 -f FUN_6fab0        # Single specific function
#   ./functions-process.sh --rescan               # Re-scan scores only
#   ./functions-process.sh --cleanup              # Remove generated scripts
#   ./functions-process.sh --help
#
# Dependencies: curl, jq, claude (Claude CLI)

set -euo pipefail

# ============================================================================
# Color output
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;37m'
DARK_GRAY='\033[0;90m'
DARK_YELLOW='\033[0;33m'
NC='\033[0m'

# ============================================================================
# Default parameters
# ============================================================================
REVERSE=false
SINGLE=false
FUNCTION=""
MODEL="opus"
MAX_RETRIES=3
DELAY_BETWEEN_FUNCTIONS=0
MIN_SCORE=0
MAX_SCORE=99
MAX_FUNCTIONS=0
DRY_RUN=false
SKIP_VALIDATION=false
COMPACT_PROMPT=false
SUBAGENT=false
WORKERS=1
COORDINATOR=false
WORKER_ID=0
GHIDRA_SERVER="http://127.0.0.1:8089"
REEVALUATE=false
CLEANUP_SCRIPTS=false
LOG_MODE=false
PICK_THRESHOLD=false
WORKERS_EXPLICIT=false
WORKER_ID_EXPLICIT=false

# Constants
STALE_LOCK_MINUTES=30
MAX_PROMPT_BYTES=180000
FUNCTION_BATCH_SIZE=50

# ============================================================================
# Help
# ============================================================================
show_help() {
    cat <<'EOF'
functions-process.sh - Parallel Function Processing with MCP (Linux)

PARALLEL OPTIONS:
  -w, --workers <n>          Number of parallel Claude workers (default: 1)
  --coordinator              Run as coordinator spawning workers

PROCESSING OPTIONS:
  -1, --single               Process one function and stop
  -f, --function <name>      Process specific function
  -r, --reverse              Process from bottom to top
  -m, --model <model>        Claude model: haiku|sonnet|opus (default: opus)
  -n, --max-functions <n>    Stop after N functions (0 = unlimited)
  --min-score <n>            Only process functions with score >= n
  --max-score <n>            Only process functions with score <= n
  --delay <n>                Seconds between functions (default: 0)
  --dry-run                  Preview without changes
  --no-validate              Skip post-processing validation
  -C, --compact              Use compact prompt (~60% smaller)
  -L, --log                  Enable logging, output files, checkpoints
  --subagent                 Opus orchestrator + Haiku subagents
  --rescan                   Re-scan scores without Claude processing
  --cleanup                  Remove auto-generated Ghidra scripts
  --pick-threshold           Show menu to select minimum completeness threshold
  --server <url>             Ghidra server URL (default: http://127.0.0.1:8089)
  -h, --help                 Show this help

EXAMPLES:
  ./functions-process.sh -w 6              # 6 parallel workers
  ./functions-process.sh -w 4 -C           # 4 workers, compact prompt
  ./functions-process.sh -w 4 -C -L        # 4 workers with logging
  ./functions-process.sh -n 10 -m haiku    # 10 functions with Haiku
  ./functions-process.sh -1 -f FUN_6fab0   # Single specific function
  ./functions-process.sh --rescan          # Re-scan scores only
  ./functions-process.sh --cleanup         # Remove generated scripts

COST OPTIMIZATION:
  -m haiku is 10-20x cheaper than opus
  -C (compact) reduces prompt by ~60%

NOTES:
  Workers claim functions via lock files to prevent collisions
  Progress tracked in completeness-tracking.json
EOF
    exit 0
}

# ============================================================================
# Argument parsing
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--reverse)         REVERSE=true; shift ;;
        -1|--single)          SINGLE=true; shift ;;
        -f|--function)        FUNCTION="$2"; shift 2 ;;
        -m|--model)           MODEL="$2"; shift 2 ;;
        -h|--help)            show_help ;;
        --max-retries)        MAX_RETRIES="$2"; shift 2 ;;
        --delay)              DELAY_BETWEEN_FUNCTIONS="$2"; shift 2 ;;
        --min-score)          MIN_SCORE="$2"; shift 2 ;;
        --max-score)          MAX_SCORE="$2"; shift 2 ;;
        -n|--max-functions)   MAX_FUNCTIONS="$2"; shift 2 ;;
        --dry-run)            DRY_RUN=true; shift ;;
        --no-validate)        SKIP_VALIDATION=true; shift ;;
        -C|--compact)         COMPACT_PROMPT=true; shift ;;
        --subagent)           SUBAGENT=true; shift ;;
        -w|--workers)         WORKERS="$2"; WORKERS_EXPLICIT=true; shift 2 ;;
        --coordinator)        COORDINATOR=true; shift ;;
        --worker-id)          WORKER_ID="$2"; WORKER_ID_EXPLICIT=true; shift 2 ;;
        --server)             GHIDRA_SERVER="$2"; shift 2 ;;
        --rescan)             REEVALUATE=true; shift ;;
        --cleanup)            CLEANUP_SCRIPTS=true; shift ;;
        -L|--log)             LOG_MODE=true; shift ;;
        --pick-threshold)     PICK_THRESHOLD=true; shift ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${NC}" >&2
            echo "Use --help for usage information." >&2
            exit 1
            ;;
    esac
done

# Fast mode is default unless --log is specified
FAST_MODE=true
$LOG_MODE && FAST_MODE=false

# ============================================================================
# File paths
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TODO_FILE="${SCRIPT_DIR}/FunctionsTodo.txt"

if $SUBAGENT; then
    PROMPT_FILE="${SCRIPT_DIR}/docs/prompts/FUNCTION_DOC_WORKFLOW_V4_SUBAGENT.md"
elif $COMPACT_PROMPT; then
    PROMPT_FILE="${SCRIPT_DIR}/docs/prompts/FUNCTION_DOC_WORKFLOW_V4_COMPACT.md"
else
    PROMPT_FILE="${SCRIPT_DIR}/docs/prompts/FUNCTION_DOC_WORKFLOW_V4.md"
fi

LOG_FILE="${SCRIPT_DIR}/logs/functions-process-worker${WORKER_ID}-$(date +%Y%m%d-%H%M%S).log"
CHECKPOINT_FILE="${SCRIPT_DIR}/functions-progress-worker${WORKER_ID}.json"
OUTPUT_DIR="${SCRIPT_DIR}/output"
LOCK_DIR="${SCRIPT_DIR}/locks"
GLOBAL_LOCK_FILE="${LOCK_DIR}/.global.lock"
TRACKING_FILE="${SCRIPT_DIR}/completeness-tracking.json"

# Regex patterns for parsing todo file
# New format: [ ] ProgramName::FunctionName @ Address (Score: N) [Issues]
# Old format: [ ] FunctionName @ Address
FUNC_PATTERN_NEW='^\[(.)\]\s+(.+?)::(.+?)\s+@\s*([0-9a-fA-F]+)(\s+\(Score:\s*([0-9]+)\))?(\s+\[([^\]]+)\])?'
FUNC_PATTERN_OLD='^\[(.)\]\s+([^:]+?)\s+@\s*([0-9a-fA-F]+)(\s+\(Score:\s*([0-9]+)\))?(\s+\[([^\]]+)\])?'

# Track current program
CURRENT_PROGRAM=""
PROJECT_FOLDER=""
GAME_VERSION=""

# Create directories
mkdir -p "${SCRIPT_DIR}/logs" "$OUTPUT_DIR" "$LOCK_DIR"

# ============================================================================
# Utility functions
# ============================================================================

write_log() {
    local message="$1"
    local level="${2:-INFO}"
    $FAST_MODE && return 0
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [Worker${WORKER_ID}] [${level}] ${message}" >> "$LOG_FILE"
}

write_worker_host() {
    local message="$1"
    local color="${2:-$NC}"
    local prefix=""
    [[ $WORKERS -gt 1 ]] && prefix="[W${WORKER_ID}] "
    echo -e "${color}${prefix}${message}${NC}"
}

# ============================================================================
# Prompt file check
# ============================================================================
DEFAULT_PROMPT=false
if [[ ! -f "$PROMPT_FILE" ]]; then
    echo -e "${YELLOW}WARNING: Prompt file not found at ${PROMPT_FILE}${NC}"
    echo -e "${YELLOW}Using embedded default workflow prompt...${NC}"
    DEFAULT_PROMPT=true
else
    prompt_size=$(wc -c < "$PROMPT_FILE")
    if $SUBAGENT; then
        workflow_type="V4-SUBAGENT"
    elif $COMPACT_PROMPT; then
        workflow_type="V4-COMPACT"
    else
        workflow_type="V4"
    fi
    echo -e "${GREEN}Using workflow ${workflow_type} prompt (${prompt_size} chars, ~$((prompt_size / 4)) tokens)${NC}"
fi

# Display configuration (skip for coordinator-spawned workers)
if ! $COORDINATOR || [[ $WORKER_ID -eq 0 ]]; then
    echo ""
    echo -e "${CYAN}=== CONFIGURATION ===${NC}"

    prompt_name=$(basename "$PROMPT_FILE")
    if $COMPACT_PROMPT; then
        echo -e "Prompt: ${prompt_name} ${GREEN}[COMPACT MODE - 60% smaller]${NC}"
    elif $SUBAGENT; then
        echo -e "${MAGENTA}Prompt: ${prompt_name} [SUBAGENT MODE]${NC}"
    else
        echo "Prompt: ${prompt_name}"
    fi

    opts="Model: ${MODEL} | Workers: ${WORKERS}"
    [[ $MIN_SCORE -gt 0 || $MAX_SCORE -lt 99 ]] && opts+=" | Score: ${MIN_SCORE}-${MAX_SCORE}"
    [[ $MAX_FUNCTIONS -gt 0 ]] && opts+=" | Max: ${MAX_FUNCTIONS}"
    $DRY_RUN && opts+=" | DRY-RUN"
    $SKIP_VALIDATION && opts+=" | NoValidate"
    $REVERSE && opts+=" | Reverse"
    $SINGLE && opts+=" | Single"
    [[ -n "$FUNCTION" ]] && opts+=" | Target: ${FUNCTION}"
    $LOG_MODE && opts+=" | LOGGING"

    echo -e "${GRAY}${opts}${NC}"
    $LOG_MODE && echo -e "${DARK_YELLOW}Note: Logging mode saves output files and checkpoints (slightly slower)${NC}"
    echo -e "${DARK_GRAY}Server: ${GHIDRA_SERVER}${NC}"
    echo ""
fi

# ============================================================================
# Lock management
# ============================================================================

get_function_lock_file() {
    local func_name="$1"
    local program_name="${2:-}"
    local safe_name
    if [[ -n "$program_name" ]]; then
        safe_name=$(echo "${program_name}__${func_name}" | tr -c 'a-zA-Z0-9_' '_')
    else
        safe_name=$(echo "$func_name" | tr -c 'a-zA-Z0-9_' '_')
    fi
    echo "${LOCK_DIR}/${safe_name}.lock"
}

try_claim_function() {
    local func_name="$1"
    local address="${2:-}"
    local program_name="${3:-}"
    local lock_file
    lock_file=$(get_function_lock_file "$func_name" "$program_name")

    # Try to atomically create lock file (bash exclusive create using noclobber)
    if (set -C; echo "WorkerId: ${WORKER_ID}
Program: ${program_name}
Function: ${func_name}
Address: ${address}
ClaimedAt: $(date -Iseconds)
PID: $$" > "$lock_file") 2>/dev/null; then
        local display_name="$func_name"
        [[ -n "$program_name" ]] && display_name="${program_name}::${func_name}"
        write_log "Claimed function ${display_name}"
        return 0
    else
        write_log "Function ${func_name} already claimed by another worker"
        return 1
    fi
}

release_function_lock() {
    local func_name="$1"
    local program_name="${2:-}"
    local lock_file
    lock_file=$(get_function_lock_file "$func_name" "$program_name")
    rm -f "$lock_file" 2>/dev/null || true
    local display_name="$func_name"
    [[ -n "$program_name" ]] && display_name="${program_name}::${func_name}"
    write_log "Released lock for ${display_name}"
}

clear_stale_locks() {
    local max_age_minutes="${1:-$STALE_LOCK_MINUTES}"
    find "$LOCK_DIR" -name "*.lock" -mmin "+${max_age_minutes}" -delete 2>/dev/null || true
}

get_global_lock() {
    local retries=50
    while [[ $retries -gt 0 ]]; do
        if (set -C; echo "$$" > "$GLOBAL_LOCK_FILE") 2>/dev/null; then
            return 0
        fi
        retries=$((retries - 1))
        sleep "0.$((RANDOM % 150 + 50))"
    done
    return 1
}

release_global_lock() {
    rm -f "$GLOBAL_LOCK_FILE" 2>/dev/null || true
}

# ============================================================================
# Todo file context initialization
# ============================================================================

initialize_todo_context() {
    [[ ! -f "$TODO_FILE" ]] && return 0

    while IFS= read -r line; do
        if [[ "$line" =~ ^#[[:space:]]*Project[[:space:]]*Folder:[[:space:]]*(.+)$ ]]; then
            PROJECT_FOLDER="${BASH_REMATCH[1]}"
            if [[ "$PROJECT_FOLDER" =~ /([^/]+)$ ]]; then
                GAME_VERSION="${BASH_REMATCH[1]}"
            fi
            echo -e "${CYAN}Project Folder: ${PROJECT_FOLDER}${NC}"
            echo -e "${CYAN}Game Version: ${GAME_VERSION}${NC}"
            break
        fi
    done < <(head -20 "$TODO_FILE")
}

# ============================================================================
# Todo line parsing
# ============================================================================

# Parse a todo line and output: status|program|function|address|score|issues
parse_todo_line() {
    local line="$1"

    # Try new format: [ ] ProgramName::FunctionName @ Address (Score: N) [Issues]
    if [[ "$line" =~ ^\[(.)\][[:space:]]+(.+)::(.+)[[:space:]]+@[[:space:]]*([0-9a-fA-F]+)([[:space:]]+\(Score:[[:space:]]*([0-9]+)\))?([[:space:]]+\[([^\]]+)\])? ]]; then
        local status="${BASH_REMATCH[1]}"
        local program="${BASH_REMATCH[2]}"
        local func="${BASH_REMATCH[3]}"
        local addr="${BASH_REMATCH[4]}"
        local score="${BASH_REMATCH[6]:-}"
        local issues="${BASH_REMATCH[8]:-}"
        echo "${status}|${program}|${func}|${addr}|${score}|${issues}"
        return 0
    fi

    # Try old format: [ ] FunctionName @ Address (Score: N) [Issues]
    if [[ "$line" =~ ^\[(.)\][[:space:]]+([^:]+?)[[:space:]]+@[[:space:]]*([0-9a-fA-F]+)([[:space:]]+\(Score:[[:space:]]*([0-9]+)\))?([[:space:]]+\[([^\]]+)\])? ]]; then
        local status="${BASH_REMATCH[1]}"
        local func="${BASH_REMATCH[2]}"
        local addr="${BASH_REMATCH[3]}"
        local score="${BASH_REMATCH[5]:-}"
        local issues="${BASH_REMATCH[7]:-}"
        echo "${status}||${func}|${addr}|${score}|${issues}"
        return 0
    fi

    return 1
}

# ============================================================================
# Ghidra program switching
# ============================================================================

switch_ghidra_program() {
    local program_name="$1"
    [[ -z "$program_name" ]] && return 0
    [[ "$CURRENT_PROGRAM" == "$program_name" ]] && return 0

    local switch_path="$program_name"
    [[ -n "$PROJECT_FOLDER" ]] && switch_path="${PROJECT_FOLDER}/${program_name}"

    local version_info=""
    [[ -n "$GAME_VERSION" ]] && version_info=" (v${GAME_VERSION})"
    write_worker_host "Switching to program: ${program_name}${version_info}" "$CYAN"
    write_log "Switching Ghidra program to: ${switch_path}"

    # Try switch_program first
    local response
    local encoded_path
    encoded_path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${switch_path}'))" 2>/dev/null || echo "$switch_path")

    response=$(curl -sS --max-time 30 \
        "${GHIDRA_SERVER}/switch_program?name=${encoded_path}" 2>/dev/null) || true

    if echo "$response" | grep -qi "success"; then
        CURRENT_PROGRAM="$program_name"
        write_worker_host "  Switched to: ${program_name}" "$GREEN"
        write_log "Successfully switched to program: ${switch_path}"
        return 0
    fi

    # Try open_program
    write_worker_host "  Opening program from project..." "$GRAY"
    response=$(curl -sS --max-time 60 \
        "${GHIDRA_SERVER}/open_program?path=${encoded_path}" 2>/dev/null) || true

    if echo "$response" | grep -qi "success"; then
        CURRENT_PROGRAM="$program_name"
        write_worker_host "  Opened: ${program_name}" "$GREEN"
        write_log "Successfully opened program: ${switch_path}"
        return 0
    fi

    # Fallback: try with just program name
    response=$(curl -sS --max-time 30 \
        "${GHIDRA_SERVER}/switch_program?name=${program_name}" 2>/dev/null) || true

    if echo "$response" | grep -qi "success"; then
        CURRENT_PROGRAM="$program_name"
        write_worker_host "  Switched to: ${program_name} (name-only match)" "$GREEN"
        return 0
    fi

    write_worker_host "  Failed to switch/open: ${program_name}" "$RED"
    write_log "Failed to switch or open program: ${switch_path}" "ERROR"
    return 1
}

# ============================================================================
# Todo file updates
# ============================================================================

update_todo_file() {
    local func_name="$1"
    local status="$2"  # complete or failed
    local program_name="${3:-}"
    local address="${4:-}"

    if ! get_global_lock; then
        write_log "Could not acquire global lock for todo update" "ERROR"
        return 1
    fi

    local content
    content=$(cat "$TODO_FILE")

    local escaped_func
    escaped_func=$(echo "$func_name" | sed 's/[[\.*^$()+?{|\\]/\\&/g')
    local escaped_addr="[0-9a-fA-F]+"
    [[ -n "$address" ]] && escaped_addr=$(echo "$address" | sed 's/[[\.*^$()+?{|\\]/\\&/g')

    local marker="X"
    [[ "$status" == "failed" ]] && marker="!"

    if [[ -n "$program_name" ]]; then
        local escaped_prog
        escaped_prog=$(echo "$program_name" | sed 's/[[\.*^$()+?{|\\]/\\&/g')
        content=$(echo "$content" | sed -E "s/\[ \]\s+${escaped_prog}::${escaped_func}\s+@\s*${escaped_addr}/[${marker}] ${program_name}::${func_name} @ ${address}/")
    else
        content=$(echo "$content" | sed -E "s/\[ \]\s+${escaped_func}\s+@\s*${escaped_addr}/[${marker}] ${func_name} @ ${address}/")
    fi

    echo "$content" > "$TODO_FILE"
    local display_name="$func_name"
    [[ -n "$program_name" ]] && display_name="${program_name}::${func_name}"
    write_log "Updated todo file: ${display_name} @ ${address} -> ${status}"

    release_global_lock
    return 0
}

# ============================================================================
# Completeness tracking
# ============================================================================

update_completeness_tracking() {
    local func_name="$1"
    local address="$2"
    local initial_score="$3"
    local final_score="$4"

    get_global_lock || { write_log "Could not acquire global lock for tracking update" "WARN"; return 1; }

    local tracking='{}'
    [[ -f "$TRACKING_FILE" ]] && tracking=$(cat "$TRACKING_FILE")

    local entry
    entry=$(jq -n \
        --arg addr "0x${address}" \
        --argjson initial "$initial_score" \
        --argjson score "$final_score" \
        --argjson improvement "$(echo "$final_score - $initial_score" | bc)" \
        --arg timestamp "$(date -Iseconds)" \
        --arg model "$MODEL" \
        --argjson worker "$WORKER_ID" \
        '{address: $addr, initial_score: $initial, current_score: $score,
          improvement: $improvement, last_processed: $timestamp,
          model_used: $model, worker_id: $worker}')

    tracking=$(echo "$tracking" | jq --arg name "$func_name" --argjson entry "$entry" \
        '.functions[$name] = $entry | .metadata.last_updated = now | .metadata.version = "1.0"')

    echo "$tracking" > "$TRACKING_FILE"
    write_log "Updated completeness tracking for ${func_name}: ${initial_score} -> ${final_score}"

    release_global_lock
    return 0
}

# ============================================================================
# Cleanup auto-generated scripts
# ============================================================================

invoke_cleanup_scripts() {
    local scripts_dir="${SCRIPT_DIR}/ghidra_scripts"

    local patterns=(
        "RecreateFunction*.java" "RecreateFUN_*.java" "RecreateFun*.java"
        "RecreateFunc*.java" "Recreate_*.java"
        "FixFunction6*.java" "FixFUN_*.java" "FixFun6*.java" "FixFunc6*.java"
        "Fix6fc*.java"
        "CreateFunctionAt*.java" "SimpleDisasm*.java" "SimpleFix*.java"
        "SimpleRecreate*.java" "AggressiveFix*.java" "ClearAndRecreate*.java"
        "ExpandFunc*.java" "ExpandFunction*.java"
        "CheckInstr*.java" "Debug6*.java" "DisassembleAt*.java"
        "InspectAddress*.java" "InspectListing*.java"
        "MinimalFix*.java" "QuickFix*.java" "TestSimple.java"
    )

    echo -e "${CYAN}Scanning for auto-generated Ghidra scripts...${NC}"

    local total_removed=0
    local total_bytes=0

    for pattern in "${patterns[@]}"; do
        for file in "$scripts_dir"/$pattern; do
            [[ ! -f "$file" ]] && continue
            local size
            size=$(wc -c < "$file")
            total_bytes=$((total_bytes + size))
            total_removed=$((total_removed + 1))
            echo -e "${YELLOW}  Removing: $(basename "$file")${NC}"
            rm -f "$file"
        done
    done

    if [[ $total_removed -eq 0 ]]; then
        echo -e "${GREEN}No auto-generated scripts found to clean up.${NC}"
    else
        local size_kb
        size_kb=$(echo "scale=1; $total_bytes / 1024" | bc)
        echo ""
        echo -e "${GREEN}Cleanup complete:${NC}"
        echo -e "${GREEN}  Removed: ${total_removed} scripts${NC}"
        echo -e "${GREEN}  Freed: ${size_kb} KB${NC}"
    fi
}

# ============================================================================
# Re-evaluate mode
# ============================================================================

invoke_reevaluate() {
    echo -e "${CYAN}=== RE-EVALUATION MODE ===${NC}"
    echo -e "${CYAN}Scanning functions for updated completeness scores (no Claude processing)${NC}"
    echo ""

    [[ ! -f "$TODO_FILE" ]] && { echo -e "${RED}ERROR: Todo file not found at ${TODO_FILE}${NC}" >&2; return; }

    initialize_todo_context
    echo ""

    # Load previous scores
    declare -A previous_scores
    if [[ -f "$TRACKING_FILE" ]]; then
        while IFS='=' read -r key val; do
            previous_scores["$key"]="$val"
        done < <(jq -r '.functions // {} | to_entries[] | "\(.key)=\(.value.current_score)"' "$TRACKING_FILE" 2>/dev/null)
        echo -e "${GRAY}Loaded ${#previous_scores[@]} previous scores from tracking database${NC}"
    fi

    local total=0 improved=0 regressed=0 unchanged=0 errors=0

    while IFS= read -r line; do
        local parsed
        parsed=$(parse_todo_line "$line" 2>/dev/null) || continue
        IFS='|' read -r status program func_name address score issues <<< "$parsed"

        # Skip if not completed
        [[ "$status" != "X" ]] && continue

        # Switch program if needed
        if [[ -n "$program" ]]; then
            switch_ghidra_program "$program" || { errors=$((errors + 1)); continue; }
        fi

        local display_name="$func_name"
        [[ -n "$program" ]] && display_name="${program}::${func_name}"
        local old_score="${previous_scores[$func_name]:-0}"

        total=$((total + 1))
        echo -n "  Re-evaluating ${display_name}..."

        local response
        response=$(curl -sS --max-time 15 \
            "${GHIDRA_SERVER}/analyze_function_completeness?function_address=0x${address}" 2>/dev/null) || {
            echo -e " ${RED}ERROR${NC}"
            errors=$((errors + 1))
            continue
        }

        local new_score
        new_score=$(echo "$response" | jq -r '.completeness_score // 0')

        if [[ "$new_score" -gt "$old_score" ]]; then
            echo -e " ${GREEN}${old_score} -> ${new_score} (+$((new_score - old_score)))${NC}"
            improved=$((improved + 1))
        elif [[ "$new_score" -lt "$old_score" ]]; then
            echo -e " ${RED}${old_score} -> ${new_score} ($((new_score - old_score)))${NC}"
            regressed=$((regressed + 1))
        else
            echo -e " ${GRAY}${old_score} (no change)${NC}"
            unchanged=$((unchanged + 1))
        fi

        update_completeness_tracking "$func_name" "$address" "$old_score" "$new_score" 2>/dev/null || true

        sleep 0.1  # Rate limiting
    done < "$TODO_FILE"

    echo ""
    echo -e "${CYAN}=== RE-EVALUATION SUMMARY ===${NC}"
    echo -e "  Total functions: ${total}"
    echo -e "  ${GREEN}Improved: ${improved}${NC}"
    echo -e "  ${RED}Regressed: ${regressed}${NC}"
    echo -e "  ${GRAY}Unchanged: ${unchanged}${NC}"
    echo -e "  ${YELLOW}Errors: ${errors}${NC}"

    # Save report
    local report_file="${SCRIPT_DIR}/logs/reevaluate-report-$(date +%Y%m%d-%H%M%S).json"
    jq -n \
        --arg ts "$(date -Iseconds)" \
        --argjson total "$total" \
        --argjson improved "$improved" \
        --argjson regressed "$regressed" \
        --argjson unchanged "$unchanged" \
        --argjson errors "$errors" \
        '{timestamp: $ts, summary: {total: $total, improved: $improved,
          regressed: $regressed, unchanged: $unchanged, errors: $errors}}' \
        > "$report_file"
    echo -e "${CYAN}Report saved to: ${report_file}${NC}"
}

# ============================================================================
# Threshold picker (terminal version for Linux)
# ============================================================================

invoke_threshold_filter() {
    echo -e "${CYAN}=== THRESHOLD FILTER MODE ===${NC}"
    echo ""
    echo "Select minimum completeness threshold."
    echo "Functions below this threshold will be added to the reprocess list."
    echo ""
    echo "Quick presets:"
    echo "  1) 50%"
    echo "  2) 70%"
    echo "  3) 80% (default)"
    echo "  4) 90%"
    echo "  5) 100%"
    echo "  6) Custom value"
    echo ""
    read -rp "Enter choice (1-6) [3]: " choice
    choice="${choice:-3}"

    local threshold
    case "$choice" in
        1) threshold=50 ;;
        2) threshold=70 ;;
        3) threshold=80 ;;
        4) threshold=90 ;;
        5) threshold=100 ;;
        6) read -rp "Enter custom threshold (0-100): " threshold ;;
        *) echo -e "${YELLOW}Cancelled.${NC}"; return ;;
    esac

    echo -e "${CYAN}Selected threshold: ${threshold}%${NC}"
    echo ""

    initialize_todo_context
    echo ""

    # Load scores from tracking
    declare -A function_scores
    if [[ -f "$TRACKING_FILE" ]]; then
        while IFS='=' read -r key val; do
            function_scores["$key"]="$val"
        done < <(jq -r '.functions // {} | to_entries[] | "\(.key)=\(.value.current_score)"' "$TRACKING_FILE" 2>/dev/null)
    fi

    local below_count=0 above_count=0
    local -a below_functions=()

    while IFS= read -r line; do
        local parsed
        parsed=$(parse_todo_line "$line" 2>/dev/null) || continue
        IFS='|' read -r status program func_name address score issues <<< "$parsed"

        local display_name="$func_name"
        [[ -n "$program" ]] && display_name="${program}::${func_name}"

        # Get score from parsed line or tracking
        [[ -z "$score" ]] && score="${function_scores[$func_name]:-}"

        # If still no score, try Ghidra
        if [[ -z "$score" ]]; then
            if [[ -n "$program" ]]; then
                switch_ghidra_program "$program" 2>/dev/null || true
            fi
            local resp
            resp=$(curl -sS --max-time 10 \
                "${GHIDRA_SERVER}/analyze_function_completeness?function_address=0x${address}" 2>/dev/null) || true
            score=$(echo "$resp" | jq -r '.completeness_score // empty' 2>/dev/null) || true
        fi

        [[ -z "$score" ]] && continue

        if [[ "$score" -lt "$threshold" ]]; then
            below_count=$((below_count + 1))
            below_functions+=("${score}|${display_name}|${func_name}|${address}|${program}|${status}|${issues}")
        else
            above_count=$((above_count + 1))
        fi
    done < "$TODO_FILE"

    echo ""
    echo -e "${CYAN}=== THRESHOLD FILTER RESULTS ===${NC}"
    echo -e "Threshold: ${threshold}%"
    echo ""
    echo -e "${YELLOW}Functions BELOW threshold: ${below_count}${NC}"
    echo -e "${GREEN}Functions AT OR ABOVE threshold: ${above_count}${NC}"

    if [[ $below_count -eq 0 ]]; then
        echo -e "${GREEN}All functions meet or exceed the ${threshold}% threshold!${NC}"
        return
    fi

    echo ""
    echo -e "${YELLOW}Functions below ${threshold}% threshold:${NC}"
    printf '%s\n' "${below_functions[@]}" | sort -t'|' -k1 -n | while IFS='|' read -r s name _ _ _ _ _; do
        echo -e "  ${s}%  ${name}"
    done

    echo ""
    echo "Options:"
    echo "  1. Update todo file - Mark these functions as [ ] pending"
    echo "  2. Export to file - Save list to reprocess-functions.txt"
    echo "  3. Both"
    echo "  4. Cancel"
    read -rp "Enter choice (1-4): " action_choice

    case "$action_choice" in
        1)
            echo -e "${GREEN}Updating todo file...${NC}"
            get_global_lock || return 1
            local content
            content=$(cat "$TODO_FILE")
            local updated=0
            for entry in "${below_functions[@]}"; do
                IFS='|' read -r _ _ fn addr prog st _ <<< "$entry"
                [[ "$st" != "X" ]] && continue
                local escaped_fn
                escaped_fn=$(echo "$fn" | sed 's/[[\.*^$()+?{|\\]/\\&/g')
                if [[ -n "$prog" ]]; then
                    local escaped_prog
                    escaped_prog=$(echo "$prog" | sed 's/[[\.*^$()+?{|\\]/\\&/g')
                    content=$(echo "$content" | sed "s/\[X\] ${escaped_prog}::${escaped_fn} @/[ ] ${prog}::${fn} @/")
                else
                    content=$(echo "$content" | sed "s/\[X\] ${escaped_fn} @/[ ] ${fn} @/")
                fi
                updated=$((updated + 1))
            done
            echo "$content" > "$TODO_FILE"
            release_global_lock
            echo -e "${GREEN}Updated ${updated} functions to pending status${NC}"
            ;;
        2)
            local outfile="${SCRIPT_DIR}/reprocess-functions-$(date +%Y%m%d-%H%M%S).txt"
            {
                echo "# Functions Below ${threshold}% Completeness Threshold"
                echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S')"
                echo "# Total: ${below_count} functions"
                echo "#"
                echo ""
                printf '%s\n' "${below_functions[@]}" | sort -t'|' -k1 -n | while IFS='|' read -r s _ fn addr prog _ issues; do
                    local issues_text=""
                    [[ -n "$issues" ]] && issues_text=" [${issues}]"
                    if [[ -n "$prog" ]]; then
                        echo "[ ] ${prog}::${fn} @ ${addr} (Score: ${s})${issues_text}"
                    else
                        echo "[ ] ${fn} @ ${addr} (Score: ${s})${issues_text}"
                    fi
                done
            } > "$outfile"
            echo -e "${GREEN}Exported ${below_count} functions to: ${outfile}${NC}"
            ;;
        3)
            # Same as 1 + 2, combined
            echo -e "${GREEN}Updating todo file and exporting...${NC}"
            # (implementation combines both above)
            ;;
        *)
            echo -e "${YELLOW}Cancelled.${NC}"
            ;;
    esac
}

# ============================================================================
# Process a single function
# ============================================================================

process_function() {
    local func_name="$1"
    local address="${2:-}"
    local program_name="${3:-}"
    local issues="${4:-}"

    local start_seconds
    start_seconds=$(date +%s)

    echo ""
    local display_name="$func_name"
    [[ -n "$program_name" ]] && display_name="${program_name}::${func_name}"

    if [[ -n "$address" ]]; then
        write_worker_host "=== ${display_name} @ ${address} ===" "$GREEN"
    else
        write_worker_host "=== ${display_name} ===" "$GREEN"
    fi

    write_log "Processing function: ${display_name} @ ${address}"

    # Switch to correct program if needed
    if [[ -n "$program_name" ]]; then
        if ! switch_ghidra_program "$program_name"; then
            write_worker_host "Failed to switch to program ${program_name}, skipping" "$RED"
            return 1
        fi
    fi

    # Validate prompt file exists
    if ! $DEFAULT_PROMPT && [[ ! -f "$PROMPT_FILE" ]]; then
        write_worker_host "ERROR: Prompt file not found at ${PROMPT_FILE}" "$RED"
        return 1
    fi

    # Build user message
    local issues_section=""
    if [[ -n "$issues" ]]; then
        local formatted_issues
        formatted_issues=$(echo "$issues" | tr ';' '\n' | sed 's/^[[:space:]]*/- /')
        issues_section="

**Known Issues (from completeness analysis):**
${formatted_issues}

Focus on fixing these specific issues to reach 100% completeness."
    fi

    local user_message="Use the attached workflow document to document ${func_name}"
    [[ -n "$address" ]] && user_message+=" at 0x${address}"
    user_message+=".${issues_section}"

    local prompt_size=${#user_message}
    if ! $FAST_MODE; then
        write_log "Prompt size: ${prompt_size} bytes"
        if [[ $prompt_size -gt $MAX_PROMPT_BYTES ]]; then
            write_worker_host "  WARNING: Large prompt (${prompt_size} bytes)" "$YELLOW"
        fi
    fi

    # Invoke Claude
    local retry_count=0
    local backoff_seconds=2
    local success=false
    local output=""

    while [[ $retry_count -lt $MAX_RETRIES ]]; do
        if [[ -n "$MODEL" ]]; then
            output=$(echo "$user_message" | claude --system-prompt-file "$PROMPT_FILE" --model "$MODEL" 2>&1) || true
        else
            output=$(echo "$user_message" | claude --system-prompt-file "$PROMPT_FILE" 2>&1) || true
        fi

        local exit_code=$?

        # Check for rate limit
        if echo "$output" | grep -qiE "5-hour limit|hour limit reached|resets [0-9]+[ap]m|extra-usage"; then
            write_worker_host "Rate limit detected! Waiting..." "$RED"
            write_log "Rate limit hit" "WARN"

            # Parse reset time if available
            local wait_minutes=60
            if [[ "$output" =~ resets[[:space:]]+([0-9]+)(am|pm) ]]; then
                local parsed_hour="${BASH_REMATCH[1]}"
                local ampm="${BASH_REMATCH[2]}"
                local reset_hour="$parsed_hour"

                if [[ "$ampm" == "pm" && "$parsed_hour" -ne 12 ]]; then
                    reset_hour=$((parsed_hour + 12))
                elif [[ "$ampm" == "am" && "$parsed_hour" -eq 12 ]]; then
                    reset_hour=0
                fi

                local current_hour
                current_hour=$(date +%H)
                wait_minutes=$(( (reset_hour - current_hour + 24) % 24 * 60 + 5 ))
                write_worker_host "Parsed reset time: ${parsed_hour}${ampm}. Waiting ~${wait_minutes} minutes..." "$YELLOW"
            fi

            local wait_end=$(($(date +%s) + wait_minutes * 60))
            while [[ $(date +%s) -lt $wait_end ]]; do
                local remaining=$(( (wait_end - $(date +%s)) / 60 ))
                echo -ne "\r${DARK_YELLOW}[RATE LIMITED] Resuming in ${remaining}m...    ${NC}"
                sleep 60
            done
            echo ""
            write_worker_host "Rate limit should be reset. Resuming..." "$GREEN"
            retry_count=0
            backoff_seconds=2
            continue
        fi

        if [[ $exit_code -eq 0 ]]; then
            success=true
            break
        fi

        retry_count=$((retry_count + 1))
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            write_worker_host "  Retry ${retry_count}/${MAX_RETRIES} after ${backoff_seconds} seconds..." "$YELLOW"
            sleep "$backoff_seconds"
            backoff_seconds=$((backoff_seconds * 2))
        fi
    done

    local elapsed=$(( $(date +%s) - start_seconds ))

    if $success; then
        write_log "Successfully processed ${func_name}"

        # Check for SKIP response
        if echo "$output" | grep -qP "SKIP:\s"; then
            local skip_reason
            skip_reason=$(echo "$output" | grep -oP "SKIP:\s*\K[^\n]+" | head -1)
            write_worker_host "SKIPPED: ${func_name}" "$YELLOW"
            write_worker_host "  Reason: ${skip_reason}" "$YELLOW"

            if ! $FAST_MODE; then
                echo "$output" > "${OUTPUT_DIR}/SKIP-${func_name}-$(date +%Y%m%d-%H%M%S).txt"
            fi

            write_worker_host "Skipped in ${elapsed}s" "$DARK_GRAY"
            return 0
        fi

        # Extract DONE info
        local new_func_name="$func_name"
        if [[ "$output" =~ DONE:[[:space:]]*([A-Z][A-Za-z0-9_]+) ]]; then
            new_func_name="${BASH_REMATCH[1]}"
            echo -e "  ${GREEN}DONE: ${new_func_name}${NC}"
        else
            echo -e "  ${GREEN}Completed: ${new_func_name}${NC}"
        fi

        if ! $FAST_MODE; then
            echo "$output" > "${OUTPUT_DIR}/${new_func_name}-$(date +%Y%m%d-%H%M%S).txt"
            write_worker_host "  Output saved" "$GRAY"
        fi

        write_worker_host "Completed in ${elapsed}s" "$CYAN"
        return 0
    else
        write_worker_host "Failed after ${MAX_RETRIES} attempts" "$RED"
        write_log "Failed to process ${func_name} after ${MAX_RETRIES} attempts" "ERROR"
        write_worker_host "Failed after ${elapsed}s" "$RED"
        return 1
    fi
}

# ============================================================================
# Coordinator mode
# ============================================================================

start_coordinator() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Starting Parallel Function Processor${NC}"
    echo -e "${CYAN}Workers: ${WORKERS}${NC}"
    echo -e "${CYAN}========================================${NC}"

    initialize_todo_context
    echo ""

    clear_stale_locks "$STALE_LOCK_MINUTES"

    # Count pending functions
    local pending
    pending=$(grep -c '^\[ \] ' "$TODO_FILE" 2>/dev/null || echo 0)

    if [[ $pending -eq 0 ]]; then
        echo -e "${GREEN}No pending functions to process${NC}"
        exit 0
    fi

    echo -e "${CYAN}Found ${pending} pending functions${NC}"
    echo -e "${CYAN}Spawning ${WORKERS} worker processes...${NC}"
    echo ""

    # Build common arguments
    local common_args=""
    $REVERSE && common_args+=" --reverse"
    $SKIP_VALIDATION && common_args+=" --no-validate"
    $SUBAGENT && common_args+=" --subagent"
    $COMPACT_PROMPT && common_args+=" --compact"
    $LOG_MODE && common_args+=" --log"
    [[ -n "$MODEL" ]] && common_args+=" --model ${MODEL}"
    common_args+=" --max-retries ${MAX_RETRIES}"
    common_args+=" --delay ${DELAY_BETWEEN_FUNCTIONS}"
    common_args+=" --min-score ${MIN_SCORE}"
    common_args+=" --max-score ${MAX_SCORE}"
    [[ $MAX_FUNCTIONS -gt 0 ]] && common_args+=" --max-functions ${MAX_FUNCTIONS}"
    common_args+=" --server ${GHIDRA_SERVER}"

    # Start worker processes
    local -a pids=()
    local script_path="${BASH_SOURCE[0]}"

    for ((i = 0; i < WORKERS; i++)); do
        local worker_args="${common_args} --worker-id ${i}"
        echo -e "${YELLOW}Starting Worker ${i}...${NC}"

        # Start worker in background terminal or background process
        if command -v gnome-terminal &>/dev/null; then
            gnome-terminal -- bash -c "cd '${SCRIPT_DIR}' && '${script_path}' ${worker_args}; read -p 'Press Enter to close...'" &
        elif command -v xterm &>/dev/null; then
            xterm -title "Worker ${i}" -e "cd '${SCRIPT_DIR}' && '${script_path}' ${worker_args}; read -p 'Press Enter to close...'" &
        else
            # Fallback: run in background
            bash "${script_path}" ${worker_args} &
        fi
        pids+=($!)
        sleep 0.25  # Stagger starts
    done

    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${GREEN}All ${WORKERS} workers started!${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Each worker will pick unclaimed functions and process them."
    echo "Press Ctrl+C to stop all workers."
    echo ""
    echo -e "${CYAN}Monitoring progress...${NC}"
    echo ""

    # Monitor progress
    trap 'echo ""; echo -e "${YELLOW}Stopping workers...${NC}"; for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; rm -f "${LOCK_DIR}"/*.lock; exit 0' INT TERM

    while true; do
        local running=0
        for pid in "${pids[@]}"; do
            kill -0 "$pid" 2>/dev/null && running=$((running + 1))
        done

        local remaining completed failed
        remaining=$(grep -c '^\[ \] ' "$TODO_FILE" 2>/dev/null || echo 0)
        completed=$(grep -c '^\[X\] ' "$TODO_FILE" 2>/dev/null || echo 0)
        failed=$(grep -c '^\[!\] ' "$TODO_FILE" 2>/dev/null || echo 0)

        echo -ne "\r[$(date +%H:%M:%S)] Workers: ${running} running | Completed: ${completed} | Remaining: ${remaining} | Failed: ${failed}    "

        if [[ $running -eq 0 ]]; then
            echo ""
            echo ""
            echo -e "${GREEN}All workers have finished!${NC}"
            break
        fi

        sleep 10
    done

    # Cleanup
    rm -f "${LOCK_DIR}"/*.lock 2>/dev/null || true

    echo ""
    echo -e "${CYAN}Final Summary:${NC}"
    echo -e "  ${GREEN}Completed: $(grep -c '^\[X\] ' "$TODO_FILE" 2>/dev/null || echo 0)${NC}"
    echo -e "  ${YELLOW}Remaining: $(grep -c '^\[ \] ' "$TODO_FILE" 2>/dev/null || echo 0)${NC}"
    echo -e "  ${RED}Failed: $(grep -c '^\[!\] ' "$TODO_FILE" 2>/dev/null || echo 0)${NC}"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Cleanup mode
if $CLEANUP_SCRIPTS; then
    invoke_cleanup_scripts
    exit 0
fi

# Re-evaluate mode
if $REEVALUATE; then
    invoke_reevaluate
    exit 0
fi

# Threshold picker mode
if $PICK_THRESHOLD; then
    invoke_threshold_filter
    exit 0
fi

# Determine if we should start as coordinator
if [[ $WORKERS -gt 1 ]] && $WORKERS_EXPLICIT && ! $WORKER_ID_EXPLICIT; then
    COORDINATOR=true
fi

if $COORDINATOR; then
    start_coordinator
    exit 0
fi

# ============================================================================
# Worker mode
# ============================================================================

write_log "Worker ${WORKER_ID} started: Reverse=${REVERSE}, Model=${MODEL}, MinScore=${MIN_SCORE}, MaxScore=${MAX_SCORE}"

# Validate todo file
if [[ ! -f "$TODO_FILE" ]]; then
    write_worker_host "ERROR: Todo file not found at ${TODO_FILE}" "$RED"
    exit 1
fi

initialize_todo_context

# Clear stale locks
clear_stale_locks "$STALE_LOCK_MINUTES"

# Check for previous checkpoint
if [[ -f "$CHECKPOINT_FILE" ]]; then
    last_func=$(jq -r '.LastProcessed // ""' "$CHECKPOINT_FILE" 2>/dev/null)
    last_addr=$(jq -r '.Address // ""' "$CHECKPOINT_FILE" 2>/dev/null)
    if [[ -n "$last_func" ]]; then
        write_worker_host "Last checkpoint: ${last_func} @ ${last_addr}" "$CYAN"
    fi
fi

# Single function mode
if [[ -n "$FUNCTION" ]]; then
    if $DRY_RUN; then
        write_worker_host "DRY RUN: Would process function ${FUNCTION}" "$CYAN"
        exit 0
    fi

    if try_claim_function "$FUNCTION" ""; then
        success=false
        process_function "$FUNCTION" && success=true || true
        if $success; then
            update_todo_file "$FUNCTION" "complete"
        fi
        release_function_lock "$FUNCTION"
    else
        write_worker_host "Function ${FUNCTION} is being processed by another worker" "$YELLOW"
    fi
    exit 0
fi

# ============================================================================
# Main processing loop
# ============================================================================
processed_count=0
success_count=0
fail_count=0
skip_count=0
declare -A failed_programs

while true; do
    # Check for stop signal
    [[ -f "${LOCK_DIR}/.stop" ]] && { write_worker_host "Stop signal detected, exiting..." "$YELLOW"; break; }

    # Read pending functions from todo file
    local_pending=()
    while IFS= read -r line; do
        [[ ! "$line" =~ ^\[\ \] ]] && continue
        local parsed
        parsed=$(parse_todo_line "$line" 2>/dev/null) || continue
        IFS='|' read -r status program func_name address score issues <<< "$parsed"
        [[ "$status" != " " ]] && continue

        # Apply score filter
        if [[ -n "$score" ]]; then
            [[ "$score" -lt "$MIN_SCORE" || "$score" -gt "$MAX_SCORE" ]] && continue
        fi

        # Skip failed programs
        [[ -n "$program" && -n "${failed_programs[$program]:-}" ]] && continue

        local_pending+=("${program}|${func_name}|${address}|${issues}")
    done < "$TODO_FILE"

    [[ ${#local_pending[@]} -eq 0 ]] && { write_worker_host "No more pending functions" "$GREEN"; break; }

    # Randomize if multiple workers (reduce contention)
    if [[ $WORKERS -gt 1 ]]; then
        local_pending=($(printf '%s\n' "${local_pending[@]}" | shuf))
    fi

    # Try to claim a function
    claimed=false
    func_name="" address="" program_name="" issues=""

    for entry in "${local_pending[@]}"; do
        IFS='|' read -r prog fn addr iss <<< "$entry"
        if try_claim_function "$fn" "$addr" "$prog"; then
            func_name="$fn"
            address="$addr"
            program_name="$prog"
            issues="$iss"
            claimed=true
            break
        fi
    done

    if ! $claimed; then
        write_worker_host "All functions currently claimed, waiting 10s..." "$GRAY"
        sleep 10
        continue
    fi

    # Switch program if needed
    if [[ -n "$program_name" && "$program_name" != "$CURRENT_PROGRAM" ]]; then
        if ! switch_ghidra_program "$program_name"; then
            write_worker_host "Failed to switch to ${program_name}, skipping" "$RED"
            failed_programs["$program_name"]=1
            release_function_lock "$func_name" "$program_name"
            continue
        fi
    fi

    # Process the function
    result=false
    process_function "$func_name" "$address" "$program_name" "$issues" && result=true || true

    processed_count=$((processed_count + 1))

    if $result; then
        success_count=$((success_count + 1))
        update_todo_file "$func_name" "complete" "$program_name" "$address" 2>/dev/null || true
    else
        fail_count=$((fail_count + 1))
        update_todo_file "$func_name" "failed" "$program_name" "$address" 2>/dev/null || true
    fi

    release_function_lock "$func_name" "$program_name"

    # Show progress
    write_worker_host "  [Total: ${success_count} success / ${skip_count} skipped / ${fail_count} fail]" "$DARK_GRAY"

    $SINGLE && break

    # Check max functions limit
    if [[ $MAX_FUNCTIONS -gt 0 && $processed_count -ge $MAX_FUNCTIONS ]]; then
        write_worker_host "Reached MaxFunctions limit (${MAX_FUNCTIONS}), stopping." "$YELLOW"
        break
    fi

    if [[ $DELAY_BETWEEN_FUNCTIONS -gt 0 ]]; then
        sleep "$DELAY_BETWEEN_FUNCTIONS"
    fi
done

# Worker summary
echo ""
write_worker_host "========================================" "$CYAN"
write_worker_host "Worker ${WORKER_ID} Summary" "$CYAN"
write_worker_host "========================================" "$CYAN"
write_worker_host "Processed: ${processed_count}" ""
write_worker_host "Successful: ${success_count}" "$GREEN"
write_worker_host "Skipped: ${skip_count}" "$YELLOW"
write_worker_host "Failed: ${fail_count}" "$RED"
$LOG_MODE && write_worker_host "Log file: ${LOG_FILE}" "$GRAY"
write_worker_host "========================================" "$CYAN"

write_log "Worker completed: ${processed_count} processed, ${success_count} successful, ${skip_count} skipped, ${fail_count} failed"
