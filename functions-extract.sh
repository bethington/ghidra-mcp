#!/usr/bin/env bash
# Ghidra Function Extractor - REST API Version (Linux)
# Extracts functions from Ghidra via REST API and formats for todo list
#
# Usage:
#   ./functions-extract.sh
#   ./functions-extract.sh --program-name "Game.exe" --preview
#   ./functions-extract.sh --fun-only
#   ./functions-extract.sh --ordinals-only
#   ./functions-extract.sh --all --exclude-library
#   ./functions-extract.sh --undocumented-only --min-completeness-score 60
#   ./functions-extract.sh --refresh-all --refresh-output report.json
#   ./functions-extract.sh --help
#
# Dependencies: curl, jq

set -euo pipefail

# ============================================================================
# Color output
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
DARK_GRAY='\033[1;30m'
DARK_GREEN='\033[0;32m'
DARK_YELLOW='\033[0;33m'
DARK_RED='\033[0;31m'
NC='\033[0m'

# ============================================================================
# Default parameters
# ============================================================================
PROGRAM_NAME="Game.exe"
OUTPUT_FILE=""
GHIDRA_URL="http://127.0.0.1:8089"
BATCH_SIZE=1000
FUN_ONLY=false
ORDINALS_ONLY=false
ALL=false
UNDOCUMENTED_ONLY=false
MIN_COMPLETENESS_SCORE=80
EXCLUDE_LIBRARY=false
INCLUDE_ONLY_LIBRARY=false
INCLUDE_THUNKS=false
INCLUDE_EXTERNALS=false
PREVIEW=false
REFRESH_ALL=false
REFRESH_OUTPUT=""

# ============================================================================
# Help
# ============================================================================
show_help() {
    cat <<'EOF'
GHIDRA FUNCTION EXTRACTOR - REST API VERSION (Linux)
=====================================================

USAGE:
    ./functions-extract.sh [OPTIONS]

OPTIONS:
    --program-name <name>        Program name (default: Game.exe)
    --output-file <file>         Output file path (default: FunctionsTodo.txt)
    --ghidra-url <url>           Ghidra REST API URL (default: http://127.0.0.1:8089)
    --batch-size <number>        Functions per batch request (default: 1000)
    --fun-only                   Extract ONLY functions starting with FUN_ prefix
    --ordinals-only              Extract ONLY functions starting with Ordinal_ prefix
    --all                        Include ALL functions (including named functions)
    --undocumented-only          Filter to only include functions needing documentation
    --min-completeness-score <n> Minimum completeness score to exclude (default: 80)
    --exclude-library            Exclude library functions (starting with _, __, ___)
    --include-only-library       Include ONLY library functions
    --include-thunks             Include thunk functions (excluded by default)
    --include-externals          Include external/imported function pointers (excluded by default)
    --preview                    Show preview without writing file
    --refresh-all                Bypass FunctionsTodo.txt and evaluate completeness for ALL functions
    --refresh-output <file>      Output file for --refresh-all results (.json or .csv)
    --help, -h                   Show this help message

EXAMPLES:
    ./functions-extract.sh
    ./functions-extract.sh --program-name "Game.exe"
    ./functions-extract.sh --program-name "Server.exe" --preview
    ./functions-extract.sh --fun-only
    ./functions-extract.sh --ordinals-only
    ./functions-extract.sh --all
    ./functions-extract.sh --all --exclude-library
    ./functions-extract.sh --undocumented-only
    ./functions-extract.sh --undocumented-only --min-completeness-score 60
    ./functions-extract.sh --refresh-all
    ./functions-extract.sh --refresh-all --refresh-output report.json

DEPENDENCIES:
    curl, jq (sudo apt install curl jq)

DESCRIPTION:
    Extracts functions from Ghidra using REST API calls for the specified program.
    By default, only FUN_ and Ordinal_ prefixed functions are included.
    Thunk functions and external/imported function pointers are excluded by default.
EOF
    exit 0
}

# ============================================================================
# Argument parsing
# ============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --program-name)         PROGRAM_NAME="$2"; shift 2 ;;
        --output-file)          OUTPUT_FILE="$2"; shift 2 ;;
        --ghidra-url)           GHIDRA_URL="$2"; shift 2 ;;
        --batch-size)           BATCH_SIZE="$2"; shift 2 ;;
        --fun-only)             FUN_ONLY=true; shift ;;
        --ordinals-only)        ORDINALS_ONLY=true; shift ;;
        --all)                  ALL=true; shift ;;
        --undocumented-only)    UNDOCUMENTED_ONLY=true; shift ;;
        --min-completeness-score) MIN_COMPLETENESS_SCORE="$2"; shift 2 ;;
        --exclude-library)      EXCLUDE_LIBRARY=true; shift ;;
        --include-only-library) INCLUDE_ONLY_LIBRARY=true; shift ;;
        --include-thunks)       INCLUDE_THUNKS=true; shift ;;
        --include-externals)    INCLUDE_EXTERNALS=true; shift ;;
        --preview)              PREVIEW=true; shift ;;
        --refresh-all)          REFRESH_ALL=true; shift ;;
        --refresh-output)       REFRESH_OUTPUT="$2"; shift 2 ;;
        --help|-h)              show_help ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${NC}" >&2
            echo "Use --help for usage information." >&2
            exit 1
            ;;
    esac
done

# ============================================================================
# Dependency check
# ============================================================================
for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}ERROR: '$cmd' is required but not installed.${NC}" >&2
        echo "Install with: sudo apt install $cmd" >&2
        exit 1
    fi
done

# ============================================================================
# Validation
# ============================================================================
if $FUN_ONLY && $ORDINALS_ONLY; then
    echo -e "${RED}ERROR: Cannot specify both --fun-only and --ordinals-only${NC}" >&2
    exit 1
fi

if $ALL && $UNDOCUMENTED_ONLY; then
    echo -e "${RED}ERROR: Cannot specify both --all and --undocumented-only${NC}" >&2
    exit 1
fi

if $EXCLUDE_LIBRARY && $INCLUDE_ONLY_LIBRARY; then
    echo -e "${RED}ERROR: Cannot specify both --exclude-library and --include-only-library${NC}" >&2
    exit 1
fi

# Auto-generate output file name if not provided
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="FunctionsTodo.txt"
fi

# ============================================================================
# Refresh All Mode
# ============================================================================
if $REFRESH_ALL; then
    echo -e "${MAGENTA}GHIDRA FUNCTION COMPLETENESS SCAN - REFRESH ALL MODE${NC}"
    echo -e "${MAGENTA}=====================================================${NC}"
    echo "Ghidra URL: $GHIDRA_URL"
    echo -e "${CYAN}Scanning ALL functions directly from Ghidra (bypassing FunctionsTodo.txt)${NC}"
    echo ""

    list_api_url="${GHIDRA_URL}/list_functions_enhanced"
    completeness_api_url="${GHIDRA_URL}/analyze_function_completeness"

    # Fetch all functions
    echo -e "${YELLOW}Fetching all functions from Ghidra...${NC}"
    response=$(curl -sS --max-time 60 "${list_api_url}" 2>&1) || {
        echo -e "${RED}ERROR: Failed to connect to Ghidra at ${GHIDRA_URL}${NC}" >&2
        echo "Make sure Ghidra is running with the MCP plugin enabled." >&2
        exit 1
    }

    # Check for error
    error=$(echo "$response" | jq -r '.error // empty' 2>/dev/null)
    if [[ -n "$error" ]]; then
        echo -e "${RED}ERROR: $error${NC}" >&2
        exit 1
    fi

    total_functions=$(echo "$response" | jq '.functions | length')
    echo -e "${GREEN}Total functions found: ${total_functions}${NC}"
    echo ""
    echo -e "${YELLOW}Evaluating completeness for each function...${NC}"
    echo ""

    # Initialize counters
    declare -A score_dist=( ["100"]=0 ["90-99"]=0 ["80-89"]=0 ["70-79"]=0
                            ["60-69"]=0 ["50-59"]=0 ["40-49"]=0 ["30-39"]=0
                            ["20-29"]=0 ["10-19"]=0 ["0-9"]=0 )

    processed=0
    results_json="[]"
    start_time=$(date +%s)

    # Process each function
    for row in $(echo "$response" | jq -r '.functions[] | @base64'); do
        func=$(echo "$row" | base64 -d)
        func_name=$(echo "$func" | jq -r '.name')
        address=$(echo "$func" | jq -r '.address')
        is_thunk=$(echo "$func" | jq -r '.isThunk // false')
        is_external=$(echo "$func" | jq -r '.isExternal // false')

        # Skip thunks and externals by default
        if [[ "$is_thunk" == "true" ]] && ! $INCLUDE_THUNKS; then continue; fi
        if [[ "$is_external" == "true" ]] && ! $INCLUDE_EXTERNALS; then continue; fi

        # Get completeness
        score=-1
        completeness_response=$(curl -sS --max-time 10 \
            "${completeness_api_url}?function_address=0x${address}" 2>/dev/null) || true

        if [[ -n "$completeness_response" ]]; then
            score=$(echo "$completeness_response" | jq -r '.completeness_score // -1' 2>/dev/null)
        fi

        # Update distribution
        if [[ "$score" -eq 100 ]]; then score_dist["100"]=$((${score_dist["100"]} + 1))
        elif [[ "$score" -ge 90 ]]; then score_dist["90-99"]=$((${score_dist["90-99"]} + 1))
        elif [[ "$score" -ge 80 ]]; then score_dist["80-89"]=$((${score_dist["80-89"]} + 1))
        elif [[ "$score" -ge 70 ]]; then score_dist["70-79"]=$((${score_dist["70-79"]} + 1))
        elif [[ "$score" -ge 60 ]]; then score_dist["60-69"]=$((${score_dist["60-69"]} + 1))
        elif [[ "$score" -ge 50 ]]; then score_dist["50-59"]=$((${score_dist["50-59"]} + 1))
        elif [[ "$score" -ge 40 ]]; then score_dist["40-49"]=$((${score_dist["40-49"]} + 1))
        elif [[ "$score" -ge 30 ]]; then score_dist["30-39"]=$((${score_dist["30-39"]} + 1))
        elif [[ "$score" -ge 20 ]]; then score_dist["20-29"]=$((${score_dist["20-29"]} + 1))
        elif [[ "$score" -ge 10 ]]; then score_dist["10-19"]=$((${score_dist["10-19"]} + 1))
        elif [[ "$score" -ge 0 ]]; then score_dist["0-9"]=$((${score_dist["0-9"]} + 1))
        fi

        # Add to results
        results_json=$(echo "$results_json" | jq --arg name "$func_name" --arg addr "0x${address}" \
            --argjson score "$score" \
            '. + [{"name": $name, "address": $addr, "score": $score}]')

        processed=$((processed + 1))

        # Progress indicator
        if [[ $((processed % 50)) -eq 0 ]]; then
            elapsed=$(( $(date +%s) - start_time ))
            if [[ $elapsed -gt 0 ]]; then
                rate=$(( processed / elapsed ))
                remaining=$(( (total_functions - processed) / (rate > 0 ? rate : 1) ))
                echo -e "${DARK_GRAY}  Processed ${processed} / ${total_functions} functions (ETA: ${remaining}s)${NC}"
            fi
        fi

        # Small delay to avoid overwhelming the server
        sleep 0.05
    done

    end_time=$(date +%s)
    total_time=$((end_time - start_time))
    total_minutes=$((total_time / 60))
    total_seconds=$((total_time % 60))

    echo ""
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}COMPLETENESS SCAN COMPLETE${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo ""
    echo -e "${CYAN}Total functions scanned: ${processed}${NC}"
    echo -e "${CYAN}Total time: ${total_minutes}m ${total_seconds}s${NC}"
    echo ""
    echo -e "${YELLOW}SCORE DISTRIBUTION:${NC}"
    echo -e "  ${GREEN}100:    ${score_dist["100"]} functions${NC}"
    echo -e "  ${GREEN}90-99:  ${score_dist["90-99"]} functions${NC}"
    echo -e "  ${DARK_GREEN}80-89:  ${score_dist["80-89"]} functions${NC}"
    echo -e "  ${YELLOW}70-79:  ${score_dist["70-79"]} functions${NC}"
    echo -e "  ${YELLOW}60-69:  ${score_dist["60-69"]} functions${NC}"
    echo -e "  ${DARK_YELLOW}50-59:  ${score_dist["50-59"]} functions${NC}"
    echo -e "  ${RED}40-49:  ${score_dist["40-49"]} functions${NC}"
    echo -e "  ${RED}30-39:  ${score_dist["30-39"]} functions${NC}"
    echo -e "  ${DARK_RED}20-29:  ${score_dist["20-29"]} functions${NC}"
    echo -e "  ${DARK_RED}10-19:  ${score_dist["10-19"]} functions${NC}"
    echo -e "  ${DARK_RED}0-9:    ${score_dist["0-9"]} functions${NC}"
    echo ""

    # Calculate summary
    avg_score=$(echo "$results_json" | jq '[.[] | select(.score >= 0) | .score] | add / length | . * 10 | round / 10')
    well_documented=$(echo "$results_json" | jq '[.[] | select(.score >= 80)] | length')
    needs_work=$(echo "$results_json" | jq '[.[] | select(.score >= 0 and .score < 80)] | length')

    echo -e "${YELLOW}SUMMARY:${NC}"
    echo -e "  ${CYAN}Average completeness score: ${avg_score}%${NC}"
    echo -e "  ${GREEN}Well-documented (>= 80): ${well_documented} functions${NC}"
    echo -e "  ${YELLOW}Needs work (< 80): ${needs_work} functions${NC}"
    echo ""

    # Output to file if requested
    if [[ -n "$REFRESH_OUTPUT" ]]; then
        ext="${REFRESH_OUTPUT##*.}"
        case "$ext" in
            json)
                jq -n \
                    --arg date "$(date '+%Y-%m-%d %H:%M:%S')" \
                    --argjson total "$processed" \
                    --argjson avg "$avg_score" \
                    --argjson well "$well_documented" \
                    --argjson needs "$needs_work" \
                    --argjson functions "$results_json" \
                    '{scan_date: $date, total_functions: $total, average_score: $avg,
                      well_documented_count: $well, needs_work_count: $needs, functions: $functions}' \
                    > "$REFRESH_OUTPUT"
                echo -e "${GREEN}Results written to: ${REFRESH_OUTPUT} (JSON format)${NC}"
                ;;
            csv)
                echo "Name,Address,Score" > "$REFRESH_OUTPUT"
                echo "$results_json" | jq -r '.[] | [.name, .address, .score] | @csv' >> "$REFRESH_OUTPUT"
                echo -e "${GREEN}Results written to: ${REFRESH_OUTPUT} (CSV format)${NC}"
                ;;
            *)
                {
                    echo "# Ghidra Function Completeness Report"
                    echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "# Total functions: ${processed}"
                    echo "# Average score: ${avg_score}%"
                    echo "#"
                    echo ""
                    echo "# Functions sorted by score (lowest first):"
                    echo ""
                    echo "$results_json" | jq -r 'sort_by(.score) | .[] |
                        "\(.name) @ \(.address) - Score: \(.score)%"'
                } > "$REFRESH_OUTPUT"
                echo -e "${GREEN}Results written to: ${REFRESH_OUTPUT} (text format)${NC}"
                ;;
        esac
    else
        echo -e "${YELLOW}LOWEST SCORING FUNCTIONS (need most work):${NC}"
        echo "$results_json" | jq -r 'sort_by(.score) | .[:20] | .[] |
            "  \(.name) @ \(.address) - Score: \(.score)%"'
        echo ""
        echo -e "${DARK_GRAY}Use --refresh-output <file.json|file.csv> to save full results${NC}"
    fi

    exit 0
fi

# ============================================================================
# Normal extraction mode
# ============================================================================
echo -e "${GREEN}GHIDRA FUNCTION EXTRACTOR - REST API VERSION${NC}"
echo -e "${GREEN}=============================================${NC}"
echo "Output file: $OUTPUT_FILE"
echo "Ghidra URL: $GHIDRA_URL"
echo "Batch size: $BATCH_SIZE"

if $FUN_ONLY; then
    echo -e "${YELLOW}Function filter: FUN_ only${NC}"
elif $ORDINALS_ONLY; then
    echo -e "${YELLOW}Function filter: Ordinals only${NC}"
elif $ALL; then
    echo -e "${CYAN}Function filter: ALL functions (including named)${NC}"
else
    echo -e "${CYAN}Function filter: FUN_ and Ordinal_ only (default)${NC}"
fi

if $EXCLUDE_LIBRARY; then
    echo -e "${YELLOW}Library functions: EXCLUDED (_, __, ___)${NC}"
fi
if $INCLUDE_ONLY_LIBRARY; then
    echo -e "${YELLOW}Library functions: ONLY INCLUDED (_, __, ___)${NC}"
fi
if ! $INCLUDE_THUNKS; then
    echo -e "${CYAN}Thunk functions: EXCLUDED (default)${NC}"
else
    echo -e "${YELLOW}Thunk functions: INCLUDED${NC}"
fi
if ! $INCLUDE_EXTERNALS; then
    echo -e "${CYAN}External functions: EXCLUDED (default)${NC}"
else
    echo -e "${YELLOW}External functions: INCLUDED${NC}"
fi
if $ALL; then
    echo -e "${CYAN}Documentation filter: ALL FUNCTIONS (no completeness filtering)${NC}"
elif $UNDOCUMENTED_ONLY; then
    echo -e "${YELLOW}Documentation filter: Undocumented only${NC}"
    echo -e "${YELLOW}Min completeness score: ${MIN_COMPLETENESS_SCORE}${NC}"
else
    echo -e "${CYAN}Documentation filter: All functions (default)${NC}"
fi
echo ""

# ============================================================================
# Fetch functions
# ============================================================================
list_functions_url="${GHIDRA_URL}/list_functions_enhanced"
completeness_api_url="${GHIDRA_URL}/analyze_function_completeness"

echo -e "${CYAN}Fetching functions from Ghidra...${NC}"

response=$(curl -sS --max-time 60 "${list_functions_url}" 2>&1) || {
    echo -e "${RED}ERROR: Failed to connect to Ghidra at ${GHIDRA_URL}${NC}" >&2
    echo ""
    echo -e "${YELLOW}TROUBLESHOOTING:${NC}"
    echo "1. Make sure Ghidra is running with REST API enabled"
    echo "2. Verify the URL: $GHIDRA_URL"
    echo "3. Check if port 8089 is accessible"
    echo "4. Try: curl ${GHIDRA_URL}/health"
    exit 1
}

# Check for error in response
error=$(echo "$response" | jq -r '.error // empty' 2>/dev/null || true)
if [[ -n "$error" ]]; then
    echo -e "${RED}ERROR: $error${NC}" >&2
    exit 1
fi

content_length=${#response}
echo -e "${CYAN}Response length: ${content_length} characters${NC}"

total_received=$(echo "$response" | jq '.functions | length')
echo -e "${CYAN}Total functions received: ${total_received}${NC}"

# ============================================================================
# Filter functions
# ============================================================================
all_functions=()
total_fetched=0
filtered_count=0
library_filtered=0
thunk_filtered=0
external_filtered=0

while IFS= read -r row; do
    func_name=$(echo "$row" | jq -r '.name')
    address=$(echo "$row" | jq -r '.address' | sed 's/^0x//')
    is_thunk=$(echo "$row" | jq -r '.isThunk // false')
    is_external=$(echo "$row" | jq -r '.isExternal // false')

    # Filter thunk functions
    if [[ "$is_thunk" == "true" ]] && ! $INCLUDE_THUNKS; then
        thunk_filtered=$((thunk_filtered + 1))
        continue
    fi

    # Filter external functions
    if [[ "$is_external" == "true" ]] && ! $INCLUDE_EXTERNALS; then
        external_filtered=$((external_filtered + 1))
        continue
    fi

    # Apply function type filtering
    if $FUN_ONLY; then
        [[ "$func_name" != FUN_* ]] && continue
    elif $ORDINALS_ONLY; then
        [[ "$func_name" != Ordinal_* ]] && continue
    elif ! $ALL; then
        [[ "$func_name" != FUN_* && "$func_name" != Ordinal_* ]] && continue
    fi

    # Filter library functions
    if $EXCLUDE_LIBRARY; then
        if [[ "$func_name" =~ ^_+ ]]; then
            library_filtered=$((library_filtered + 1))
            continue
        fi
    fi

    # Include only library functions
    if $INCLUDE_ONLY_LIBRARY; then
        [[ ! "$func_name" =~ ^_+ ]] && continue
    fi

    # Check documentation completeness if --undocumented-only
    include_function=true
    if $UNDOCUMENTED_ONLY && ! $ALL; then
        completeness_response=$(curl -sS --max-time 10 \
            "${completeness_api_url}?function_address=0x${address}" 2>/dev/null) || true

        if [[ -n "$completeness_response" ]]; then
            score=$(echo "$completeness_response" | jq -r '.completeness_score // 0' 2>/dev/null)
            has_custom_name=$(echo "$completeness_response" | jq -r '.has_custom_name // false' 2>/dev/null)

            # Adjust score for default names (FUN_ or Ordinal_)
            has_real_name=false
            if [[ "$has_custom_name" == "true" ]] && \
               [[ "$func_name" != FUN_* ]] && [[ "$func_name" != Ordinal_* ]]; then
                has_real_name=true
            fi

            if [[ "$has_real_name" == "false" && "$has_custom_name" == "true" ]]; then
                score=$((score - 25))
                echo -e "${DARK_YELLOW}  Adjusted score for ${func_name}: ${score} (default name penalty)${NC}"
            fi

            if [[ "$score" -ge "$MIN_COMPLETENESS_SCORE" ]]; then
                include_function=false
                filtered_count=$((filtered_count + 1))
                echo -e "${DARK_GRAY}  Filtered ${func_name} (score: ${score} >= ${MIN_COMPLETENESS_SCORE})${NC}"
            else
                echo -e "${CYAN}  Include ${func_name} (score: ${score} < ${MIN_COMPLETENESS_SCORE})${NC}"
            fi
        fi
    fi

    if $include_function; then
        all_functions+=("[ ] ${func_name} @ ${address}")
        total_fetched=$((total_fetched + 1))
    fi
done < <(echo "$response" | jq -c '.functions[]')

echo -e "${GREEN}Processed ${total_received} functions, found ${total_fetched} matching functions${NC}"
[[ $thunk_filtered -gt 0 ]] && echo -e "${DARK_GRAY}  Filtered ${thunk_filtered} thunk functions${NC}"
[[ $external_filtered -gt 0 ]] && echo -e "${DARK_GRAY}  Filtered ${external_filtered} external functions${NC}"
[[ $library_filtered -gt 0 ]] && echo -e "${DARK_GRAY}  Filtered ${library_filtered} library functions${NC}"

# ============================================================================
# Write results
# ============================================================================
echo ""
echo -e "${GREEN}WRITING RESULTS...${NC}"

if [[ ${#all_functions[@]} -gt 0 ]]; then
    if $PREVIEW; then
        echo -e "${CYAN}PREVIEW MODE - First 10 functions:${NC}"
        for i in "${!all_functions[@]}"; do
            [[ $i -ge 10 ]] && break
            echo "  ${all_functions[$i]}"
        done
        remaining=$((${#all_functions[@]} - 10))
        [[ $remaining -gt 0 ]] && echo "  ... and ${remaining} more functions"
    else
        echo -e "${GREEN}Writing ${#all_functions[@]} functions to ${OUTPUT_FILE}...${NC}"

        # Build filter description
        if $FUN_ONLY; then function_type="FUN_ functions only"
        elif $ORDINALS_ONLY; then function_type="Ordinal_ functions only"
        else function_type="FUN_ and Ordinal_ functions"
        fi

        filter_note=""
        $ALL && filter_note=" (all functions)"
        $UNDOCUMENTED_ONLY && filter_note=" (completeness < ${MIN_COMPLETENESS_SCORE})"

        library_note=""
        $EXCLUDE_LIBRARY && library_note=" (excluding library functions)"

        # Write header
        {
            echo "# ${PROGRAM_NAME} Function Todo List"
            echo "# Format: [ ] FUN_address @ address or [ ] Ordinal_number @ address"
            echo "# Generated by functions-extract.sh on $(date)"
            echo "# Total functions: ${#all_functions[@]} (${function_type}${filter_note}${library_note})"
            if $UNDOCUMENTED_ONLY; then
                echo "# Filtered out: ${filtered_count} functions (completeness >= ${MIN_COMPLETENESS_SCORE})"
            fi
            if $EXCLUDE_LIBRARY; then
                echo "# Filtered out: ${library_filtered} library functions (_, __, ___)"
            fi
            echo "#"
            echo ""
            # Write functions
            printf '%s\n' "${all_functions[@]}"
        } > "$OUTPUT_FILE"

        echo -e "${GREEN}SUCCESS! ${#all_functions[@]} functions written to ${OUTPUT_FILE}${NC}"
    fi
else
    echo -e "${YELLOW}No functions found to write${NC}"

    if ! $PREVIEW; then
        if $FUN_ONLY; then function_type="FUN_ functions only"
        elif $ORDINALS_ONLY; then function_type="Ordinal_ functions only"
        else function_type="FUN_ and Ordinal_ functions"
        fi

        filter_note=""
        $ALL && filter_note=" (all functions)"
        $UNDOCUMENTED_ONLY && filter_note=" (completeness < ${MIN_COMPLETENESS_SCORE})"

        library_note=""
        $EXCLUDE_LIBRARY && library_note=" (excluding library functions)"

        {
            echo "# ${PROGRAM_NAME} Function Todo List"
            echo "# Format: [ ] FUN_address @ address or [ ] Ordinal_number @ address"
            echo "# Generated by functions-extract.sh on $(date)"
            echo "# No functions found (${function_type} filter${filter_note}${library_note})"
            echo "#"
            echo ""
        } > "$OUTPUT_FILE"
    fi
fi

echo ""
echo -e "${GREEN}STATISTICS:${NC}"
echo "  Total functions found: ${#all_functions[@]}"
$EXCLUDE_LIBRARY && echo -e "  ${CYAN}Filtered out (library functions): ${library_filtered}${NC}"
$UNDOCUMENTED_ONLY && echo -e "  ${CYAN}Filtered out (well-documented): ${filtered_count}${NC}"
echo "  Output file: ${OUTPUT_FILE}"
if [[ -f "$OUTPUT_FILE" ]]; then
    file_size=$(wc -c < "$OUTPUT_FILE")
    echo "  File size: ${file_size} bytes"
fi

echo ""
echo -e "${GREEN}EXTRACTION COMPLETE!${NC}"
