# GhidraMCP Headless Server Docker Image
# Multi-stage build for minimal runtime image

# =============================================================================
# Stage 1: Builder - Download Ghidra and build the plugin
# =============================================================================
FROM eclipse-temurin:21-jdk AS builder

# Build arguments
# IMPORTANT: keep GHIDRA_VERSION in sync with pom.xml's <ghidra.version>.
# The Maven build resolves ghidra:* artifacts at this exact version, and the
# install-file step below stamps that version onto the JARs we extract from
# the Ghidra release zip. A mismatch means Maven can't resolve dependencies
# (see #183). GHIDRA_DATE must match the asset filename of the chosen
# version on the upstream NSA/ghidra GitHub release.
ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605

# Install build dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Download Ghidra
WORKDIR /opt
RUN wget -q --no-check-certificate \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -O ghidra.zip || \
    wget -q --no-check-certificate \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC.zip" \
    -O ghidra.zip

RUN unzip -q ghidra.zip && \
    rm ghidra.zip && \
    mv ghidra_* ghidra

# Set Ghidra environment
ENV GHIDRA_HOME=/opt/ghidra
ENV PATH="${GHIDRA_HOME}:${PATH}"

# Install Ghidra JARs to Maven local repository
RUN mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Generic/lib/Generic.jar \
        -DgroupId=ghidra -DartifactId=Generic -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar \
        -DgroupId=ghidra -DartifactId=SoftwareModeling -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Project/lib/Project.jar \
        -DgroupId=ghidra -DartifactId=Project -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Docking/lib/Docking.jar \
        -DgroupId=ghidra -DartifactId=Docking -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Utility/lib/Utility.jar \
        -DgroupId=ghidra -DartifactId=Utility -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Gui/lib/Gui.jar \
        -DgroupId=ghidra -DartifactId=Gui -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/FileSystem/lib/FileSystem.jar \
        -DgroupId=ghidra -DartifactId=FileSystem -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Help/lib/Help.jar \
        -DgroupId=ghidra -DartifactId=Help -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Base/lib/Base.jar \
        -DgroupId=ghidra -DartifactId=Base -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar \
        -DgroupId=ghidra -DartifactId=Decompiler -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/DB/lib/DB.jar \
        -DgroupId=ghidra -DartifactId=DB -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Emulation/lib/Emulation.jar \
        -DgroupId=ghidra -DartifactId=Emulation -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Debug/Debugger-api/lib/Debugger-api.jar \
        -DgroupId=ghidra -DartifactId=Debugger-api -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Debug/Framework-TraceModeling/lib/Framework-TraceModeling.jar \
        -DgroupId=ghidra -DartifactId=Framework-TraceModeling -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Debug/Debugger-rmi-trace/lib/Debugger-rmi-trace.jar \
        -DgroupId=ghidra -DartifactId=Debugger-rmi-trace -Dversion=${GHIDRA_VERSION} -Dpackaging=jar

# Copy source code
WORKDIR /build
COPY pom.xml .
COPY src ./src
COPY lib ./lib

# Build the plugin with headless profile (skip tests for Docker build)
RUN mvn clean package -P headless -DskipTests -q

# =============================================================================
# Stage 2: Runtime - Minimal image with Ghidra and plugin
# =============================================================================
# NOTE: must be a JDK (not JRE) — Ghidra's GhidraScript OSGi loader uses
# javax.tools.ToolProvider.getSystemJavaCompiler() to compile .java scripts on
# the fly. That returns null on a JRE, causing
# "AssertException: Can't find java compiler" when running any Java script.
FROM eclipse-temurin:21-jdk

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

# Install the Jython extension shipped in the Ghidra 12.1 distribution:
# starting with 12.1 it is no longer enabled by default and must be
# unpacked into Ghidra/Extensions/ to be picked up at startup.
RUN set -eux; \
    EXT_DIR="/opt/ghidra/Extensions/Ghidra"; \
    JYTHON_ZIP="$(ls "$EXT_DIR"/*_Jython.zip 2>/dev/null | head -n1)"; \
    if [ -z "$JYTHON_ZIP" ]; then \
        echo "ERROR: Jython extension zip not found in $EXT_DIR" >&2; \
        ls -la "$EXT_DIR" >&2 || true; \
        exit 1; \
    fi; \
    mkdir -p /opt/ghidra/Ghidra/Extensions; \
    unzip -q "$JYTHON_ZIP" -d /opt/ghidra/Ghidra/Extensions/; \
    echo "Installed Jython extension: $(basename "$JYTHON_ZIP")"

# Set environment variables
ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_MCP_PORT=8089
ENV JAVA_OPTS="-Xmx4g -XX:+UseG1GC"

# Create directories
RUN mkdir -p /app /data /projects

# Copy the built headless JAR (lib directory may not exist with system-scoped deps)
# Copy the built JAR (naming may vary based on version)
COPY --from=builder /build/target/GhidraMCP-*.jar /app/GhidraMCP.jar

# Copy entrypoint script and fix line endings (Windows -> Unix)
COPY docker/entrypoint.sh /app/
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose port
EXPOSE 8089

# Volume for persistent data and projects
VOLUME ["/data", "/projects"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${GHIDRA_MCP_PORT}/check_connection || exit 1

# Set working directory
WORKDIR /app

# Entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (can be overridden)
CMD ["--port", "8089"]

