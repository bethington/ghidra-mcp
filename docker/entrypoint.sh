#!/bin/bash
# GhidraMCP Server Entrypoint Script
# Starts the Ghidra headless server and MCP bridge together

set -e

# Configuration from environment variables
PORT=${GHIDRA_MCP_PORT:-8089}
BIND_ADDRESS=${GHIDRA_MCP_BIND_ADDRESS:-"0.0.0.0"}  # Default to all interfaces for Docker
JAVA_OPTS=${JAVA_OPTS:-"-Xmx4g -XX:+UseG1GC"}
GHIDRA_USER=${GHIDRA_USER:-""}  # Set to project owner name to bypass ownership checks

# MCP bridge configuration
MCP_TRANSPORT=${MCP_TRANSPORT:-"sse"}
MCP_HOST=${MCP_HOST:-"0.0.0.0"}
MCP_PORT=${MCP_PORT:-8081}
ENABLE_MCP_BRIDGE=${ENABLE_MCP_BRIDGE:-"true"}

# Shared Ghidra server configuration
GHIDRA_SERVER_HOST=${GHIDRA_SERVER_HOST:-""}
GHIDRA_SERVER_PORT=${GHIDRA_SERVER_PORT:-""}
GHIDRA_SERVER_USER=${GHIDRA_SERVER_USER:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GhidraMCP Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Print configuration
echo -e "${YELLOW}Configuration:${NC}"
echo "  Bind Address: ${BIND_ADDRESS}"
echo "  Ghidra HTTP Port: ${PORT}"
echo "  Java Options: ${JAVA_OPTS}"
echo "  Ghidra Home: ${GHIDRA_HOME}"
if [ "${ENABLE_MCP_BRIDGE}" = "true" ]; then
    echo "  MCP Bridge: enabled"
    echo "  MCP Transport: ${MCP_TRANSPORT}"
    echo "  MCP Host: ${MCP_HOST}"
    echo "  MCP Port: ${MCP_PORT}"
else
    echo "  MCP Bridge: disabled (HTTP-only mode)"
fi
if [ -n "${GHIDRA_USER}" ]; then
    echo "  Ghidra User: ${GHIDRA_USER}"
fi
if [ -n "${GHIDRA_SERVER_HOST}" ]; then
    echo "  Server Host: ${GHIDRA_SERVER_HOST}"
    echo "  Server Port: ${GHIDRA_SERVER_PORT:-13100}"
fi
if [ -n "${GHIDRA_SERVER_USER}" ]; then
    echo "  Server User: ${GHIDRA_SERVER_USER}"
fi
echo ""

# Check Ghidra installation
if [ ! -d "${GHIDRA_HOME}" ]; then
    echo -e "${RED}Error: Ghidra not found at ${GHIDRA_HOME}${NC}"
    exit 1
fi

# Build classpath with Ghidra JARs
CLASSPATH="/app/GhidraMCP.jar"

# Add Ghidra Framework JARs
for jar in ${GHIDRA_HOME}/Ghidra/Framework/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add Ghidra Feature JARs
for jar in ${GHIDRA_HOME}/Ghidra/Features/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add Ghidra Processor JARs
for jar in ${GHIDRA_HOME}/Ghidra/Processors/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add application lib JARs
if [ -d "/app/lib" ]; then
    for jar in /app/lib/*.jar; do
        [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
    done
fi

# PID tracking for process management
JAVA_PID=""
BRIDGE_PID=""

# Handle graceful shutdown - kill both processes
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down GhidraMCP server...${NC}"
    [ -n "$BRIDGE_PID" ] && kill $BRIDGE_PID 2>/dev/null
    [ -n "$JAVA_PID" ] && kill $JAVA_PID 2>/dev/null
    wait 2>/dev/null
    exit 0
}

trap cleanup SIGTERM SIGINT

# Wait for Java server to be ready
wait_for_server() {
    local max_attempts=60
    local attempt=0
    echo -e "${YELLOW}Waiting for Ghidra headless server to start...${NC}"
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://127.0.0.1:${PORT}/check_connection > /dev/null 2>&1; then
            echo -e "${GREEN}Ghidra headless server is ready.${NC}"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    echo -e "${RED}Ghidra server failed to start within $((max_attempts * 2)) seconds${NC}"
    return 1
}

# Build command arguments
ARGS="--port ${PORT} --bind ${BIND_ADDRESS}"

# Append any passed arguments (don't replace)
if [ "$#" -gt 0 ]; then
    ARGS="${ARGS} $@"
fi

# Check if a program file should be loaded
if [ -n "${PROGRAM_FILE}" ] && [ -f "${PROGRAM_FILE}" ]; then
    echo -e "${YELLOW}Loading program: ${PROGRAM_FILE}${NC}"
    ARGS="${ARGS} --file ${PROGRAM_FILE}"
fi

# Check if a project should be loaded
if [ -n "${PROJECT_PATH}" ] && [ -d "${PROJECT_PATH}" ]; then
    echo -e "${YELLOW}Loading project: ${PROJECT_PATH}${NC}"
    ARGS="${ARGS} --project ${PROJECT_PATH}"
fi

# Build user.name option if GHIDRA_USER is set
USER_OPT=""
if [ -n "${GHIDRA_USER}" ]; then
    USER_OPT="-Duser.name=${GHIDRA_USER}"
fi

echo -e "${GREEN}Starting Ghidra headless server...${NC}"
echo ""

# Start the Java server in background
java \
    ${JAVA_OPTS} \
    ${USER_OPT} \
    -Dghidra.home=${GHIDRA_HOME} \
    -Dapplication.name=GhidraMCP \
    -classpath "${CLASSPATH}" \
    com.xebyte.headless.GhidraMCPHeadlessServer \
    ${ARGS} &
JAVA_PID=$!

if [ "${ENABLE_MCP_BRIDGE}" = "true" ]; then
    # Wait for Java server to be healthy before starting the bridge
    wait_for_server || { kill $JAVA_PID 2>/dev/null; exit 1; }

    echo -e "${GREEN}Starting MCP bridge (${MCP_TRANSPORT} on ${MCP_HOST}:${MCP_PORT})...${NC}"
    echo ""

    # Set the Ghidra server URL for the bridge
    export GHIDRA_SERVER_URL="http://127.0.0.1:${PORT}"

    /app/venv/bin/python3 /app/bridge_mcp_ghidra.py \
        --ghidra-server "http://127.0.0.1:${PORT}" \
        --transport "${MCP_TRANSPORT}" \
        --mcp-host "${MCP_HOST}" \
        --mcp-port "${MCP_PORT}" &
    BRIDGE_PID=$!

    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  GhidraMCP server is ready!${NC}"
    echo -e "${GREEN}  MCP endpoint: http://${MCP_HOST}:${MCP_PORT}/sse${NC}"
    echo -e "${GREEN}  HTTP API: http://${BIND_ADDRESS}:${PORT}${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    # Monitor both processes - exit if either dies
    while true; do
        if ! kill -0 $JAVA_PID 2>/dev/null; then
            echo -e "${RED}Ghidra headless server exited unexpectedly${NC}"
            kill $BRIDGE_PID 2>/dev/null
            exit 1
        fi
        if ! kill -0 $BRIDGE_PID 2>/dev/null; then
            echo -e "${RED}MCP bridge exited unexpectedly${NC}"
            kill $JAVA_PID 2>/dev/null
            exit 1
        fi
        sleep 5
    done
else
    # No bridge - just wait on Java server (HTTP-only mode)
    echo -e "${YELLOW}MCP bridge disabled. Running in HTTP-only mode.${NC}"
    wait $JAVA_PID
fi
