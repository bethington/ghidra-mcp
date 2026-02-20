#!/bin/bash
# GhidraMCP Headless Server Entrypoint Script

set -e

# Configuration from environment variables
PORT=${GHIDRA_MCP_PORT:-8089}
BIND_ADDRESS=${GHIDRA_MCP_BIND_ADDRESS:-"0.0.0.0"}  # Default to all interfaces for Docker
JAVA_OPTS=${JAVA_OPTS:-"-Xmx4g -XX:+UseG1GC"}
GHIDRA_USER=${GHIDRA_USER:-""}  # Set to project owner name to bypass ownership checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GhidraMCP Headless Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Print configuration
echo -e "${YELLOW}Configuration:${NC}"
echo "  Bind Address: ${BIND_ADDRESS}"
echo "  Port: ${PORT}"
echo "  Java Options: ${JAVA_OPTS}"
echo "  Ghidra Home: ${GHIDRA_HOME}"
if [ -n "${GHIDRA_USER}" ]; then
    echo "  Ghidra User: ${GHIDRA_USER}"
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

# Handle graceful shutdown
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down GhidraMCP server...${NC}"
    # The Java application handles SIGTERM
    exit 0
}

trap cleanup SIGTERM SIGINT

# Build command arguments
ARGS="--port ${PORT} --bind ${BIND_ADDRESS}"

# Add any passed arguments
if [ "$#" -gt 0 ]; then
    ARGS="$@"
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

echo -e "${GREEN}Starting server...${NC}"
echo ""

# Build user.name option if GHIDRA_USER is set
USER_OPT=""
if [ -n "${GHIDRA_USER}" ]; then
    USER_OPT="-Duser.name=${GHIDRA_USER}"
fi

# Start the server
exec java \
    ${JAVA_OPTS} \
    ${USER_OPT} \
    -Dghidra.home=${GHIDRA_HOME} \
    -Dapplication.name=GhidraMCP \
    -classpath "${CLASSPATH}" \
    com.xebyte.headless.GhidraMCPHeadlessServer \
    ${ARGS}
