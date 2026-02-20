# GhidraMCP Headless Server Docker Image
# Multi-stage build for minimal runtime image

# =============================================================================
# Stage 1: Builder - Download Ghidra and build the plugin
# =============================================================================
FROM eclipse-temurin:21-jdk AS builder

# Build arguments
ARG GHIDRA_VERSION=12.0.3
ARG GHIDRA_DATE=20260210

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
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Base/lib/Base.jar \
        -DgroupId=ghidra -DartifactId=Base -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar \
        -DgroupId=ghidra -DartifactId=Decompiler -Dversion=${GHIDRA_VERSION} -Dpackaging=jar

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
FROM eclipse-temurin:21-jre

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

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
