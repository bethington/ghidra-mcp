# Version Management Strategy

This document outlines strategies to manage the version number in a single location instead of updating 20+ files manually.

---

## Current Problem

**Status**: Version 1.9.2 is duplicated in 20+ locations:
- `pom.xml` (Maven source of truth)
- `src/main/java/com/xebyte/GhidraMCPPlugin.java` (plugin metadata)
- `src/main/resources/extension.properties` (Ghidra extension)
- `README.md` (badge + documentation)
- `CLAUDE.md` (development guide)
- `docs/TOOL_REFERENCE.md` (API reference)
- `docs/PERFORMANCE_BASELINES.md` (metrics)
- `START_HERE.md` (guide)
- Multiple other documentation files

**Problem**: Manual updates are error-prone and tedious

---

## Solution 1: Properties File (Maven-Based) ⭐ Recommended

**Effort**: 2-3 hours (implement once, automated forever)

### Implementation

**Step 1**: Create `src/main/resources/version.properties`
```properties
app.version=1.9.2
app.name=GhidraMCP
app.description=Production-ready MCP server for Ghidra
app.package=com.xebyte
ghidra.version=11.4.2
java.version=21
```

**Step 2**: Configure Maven to filter resources
In `pom.xml`, update the `<build>` section:
```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-resources-plugin</artifactId>
            <version>3.3.1</version>
            <configuration>
                <encoding>UTF-8</encoding>
                <filtering>true</filtering>
            </configuration>
        </plugin>
    </plugins>
    
    <resources>
        <resource>
            <directory>src/main/resources</directory>
            <filtering>true</filtering>
            <includes>
                <include>version.properties</include>
                <include>extension.properties</include>
            </includes>
        </resource>
    </resources>
</build>
```

**Step 3**: Update Java plugin to read properties
```java
// In GhidraMCPPlugin.java
private static String VERSION;
private static String APP_NAME;

static {
    try (InputStream input = GhidraMCPPlugin.class
            .getResourceAsStream("/version.properties")) {
        Properties props = new Properties();
        props.load(input);
        VERSION = props.getProperty("app.version", "1.9.2");
        APP_NAME = props.getProperty("app.name", "GhidraMCP");
    } catch (IOException e) {
        VERSION = "1.9.2"; // fallback
        APP_NAME = "GhidraMCP";
    }
}

@Override
public void init() {
    // Use VERSION constant instead of hardcoded string
    shortDescription = String.format("%s v%s - HTTP server plugin", APP_NAME, VERSION);
}

public void versionInfo(CharSequence baseAddress) {
    // Use VERSION constant in API responses
    version.append("  \"plugin_version\": \"" + VERSION + "\",\n");
}
```

**Step 4**: Update `extension.properties` to use Maven variable
```properties
# Before (static version in file)
version=1.9.2

# After (Maven-filtered variable)
version=${project.version}
```

**Step 5**: Create Maven plugin to update documentation files
```xml
<plugin>
    <groupId>com.google.code.maven-replacer-plugin</groupId>
    <artifactId>maven-replacer-plugin</artifactId>
    <version>1.4.1</version>
    <executions>
        <execution>
            <phase>process-sources</phase>
            <goals>
                <goal>replace</goal>
            </goals>
            <configuration>
                <includes>
                    <include>../README.md</include>
                    <include>../CLAUDE.md</include>
                    <include>../docs/TOOL_REFERENCE.md</include>
                    <include>../docs/PERFORMANCE_BASELINES.md</include>
                </includes>
                <replacements>
                    <replacement>
                        <token>(?&lt;=v)\d+\.\d+\.\d+(?= )</token>
                        <value>${project.version}</value>
                    </replacement>
                    <replacement>
                        <token>GhidraMCP-\d+\.\d+\.\d+\.zip</token>
                        <value>GhidraMCP-${project.version}.zip</value>
                    </replacement>
                </replacements>
            </configuration>
        </execution>
    </executions>
</plugin>
```

**Advantages**:
- ✅ Single source of truth: `pom.xml`
- ✅ Automatic in Java code (reads from properties file)
- ✅ Maven can automatically update documentation
- ✅ Build system enforces consistency
- ✅ Works with CI/CD automatically

**Disadvantages**:
- Requires Maven plugin configuration
- Documentation updates during build (not in git history for intermediate builds)

---

## Solution 2: Python Script to Auto-Update (CI/CD-Based)

**Effort**: 1-2 hours

### Implementation

**Step 1**: Create `scripts/sync-version.py`
```python
#!/usr/bin/env python3
"""
Sync version number across all project files from pom.xml
Run this before commit to ensure consistency.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

def get_version_from_pom():
    """Extract version from pom.xml"""
    tree = ET.parse('pom.xml')
    root = tree.getroot()
    
    # Handle Maven namespace
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    version_elem = root.find('m:version', ns)
    
    if version_elem is None:
        version_elem = root.find('version')
    
    return version_elem.text if version_elem is not None else None

def update_file(filepath, old_version, new_version):
    """Update version in a file"""
    try:
        content = Path(filepath).read_text()
        updated = re.sub(
            rf'\b{re.escape(old_version)}\b',
            new_version,
            content
        )
        
        if updated != content:
            Path(filepath).write_text(updated)
            print(f"✓ Updated {filepath}")
            return True
        return False
    except Exception as e:
        print(f"✗ Error updating {filepath}: {e}")
        return False

def main():
    current_version = get_version_from_pom()
    print(f"Version from pom.xml: {current_version}")
    
    # Files to update
    files_to_update = [
        'README.md',
        'CLAUDE.md',
        'START_HERE.md',
        'DOCUMENTATION_INDEX.md',
        'NAMING_CONVENTIONS.md',
        'docs/TOOL_REFERENCE.md',
        'docs/PERFORMANCE_BASELINES.md',
        'src/main/resources/extension.properties',
        'src/main/java/com/xebyte/GhidraMCPPlugin.java',
    ]
    
    # Find current version in files (use first file as reference)
    reference_file = Path('README.md')
    if reference_file.exists():
        content = reference_file.read_text()
        # Extract version from badge: badge/MCP-X.Y.Z-purple.svg
        match = re.search(r'MCP-(\d+\.\d+\.\d+)', content)
        if match:
            old_version = match.group(1)
            print(f"Current version in files: {old_version}")
            
            if old_version != current_version:
                print(f"Updating {len(files_to_update)} files from {old_version} to {current_version}")
                for filepath in files_to_update:
                    if Path(filepath).exists():
                        update_file(filepath, old_version, current_version)
                print("✓ All files updated!")
            else:
                print("✓ All files already synchronized")
        else:
            print("Could not find current version in README.md")
    else:
        print("README.md not found")

if __name__ == '__main__':
    main()
```

**Step 2**: Create pre-commit hook `.git/hooks/pre-commit`
```bash
#!/bin/bash
# Auto-sync version before commit
python scripts/sync-version.py

# Stage updated files
git add README.md CLAUDE.md docs/*.md src/main/resources/extension.properties
```

**Step 3**: Add to GitHub Actions workflow
```yaml
name: Sync Version
on: [pull_request]
jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: python scripts/sync-version.py
      - name: Fail if version mismatch
        run: |
          if git diff --exit-code; then
            echo "✓ Version synchronized"
          else
            echo "✗ Version mismatch detected"
            echo "Run: python scripts/sync-version.py"
            exit 1
          fi
```

**Advantages**:
- ✅ Simple to implement
- ✅ Works with any CI system
- ✅ Pre-commit hook catches mistakes locally
- ✅ Python (already in project)
- ✅ Version stays in `pom.xml` as source of truth

**Disadvantages**:
- Requires manual script execution (unless hooked)
- Documentation files still updated directly

---

## Solution 3: Build Variables + Template Substitution (Maven)

**Effort**: 1 hour (simpler than Solution 1)

### Implementation

**Step 1**: Add Maven property to `pom.xml`
```xml
<properties>
    <project.version.full>1.9.2</project.version.full>
    <ghidra.version>11.4.2</ghidra.version>
    <maven.compiler.source>21</maven.compiler.source>
</properties>

<!-- In <version> element, reference it -->
<version>${project.version.full}</version>
```

**Step 2**: Create README template `README.template.md`
```markdown
[![MCP Version](https://img.shields.io/badge/MCP-${project.version.full}-purple.svg)](...)
- **Full MCP ${project.version.full} Compatibility**
```

**Step 3**: Use Maven to generate README.md from template
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-antrun-plugin</artifactId>
    <executions>
        <execution>
            <phase>process-resources</phase>
            <goals>
                <goal>run</goal>
            </goals>
            <configuration>
                <target>
                    <copy file="README.template.md" tofile="README.md" 
                          overwrite="true">
                        <filterset>
                            <filter token="project.version.full" 
                                    value="${project.version.full}"/>
                            <filter token="ghidra.version" 
                                    value="${ghidra.version}"/>
                        </filterset>
                    </copy>
                </target>
            </configuration>
        </execution>
    </executions>
</plugin>
```

**Advantages**:
- ✅ Clean separation of concerns
- ✅ Single variable definition
- ✅ Works with standard Maven plugins
- ✅ Version automatically injected into all generated files

---

## Recommendation

**Best approach for your project: Solution 2 (Python Script)**

**Why**:
1. **Minimal setup** - One Python script, already have Python in project
2. **Git-friendly** - Doesn't require complex Maven configuration
3. **Easy to audit** - Can see version changes in git diff
4. **Non-intrusive** - Doesn't change build system
5. **Works anywhere** - macOS, Linux, Windows
6. **CI/CD ready** - Easy GitHub Actions integration

**Implementation timeline**: 
- Create `scripts/sync-version.py` - 20 minutes
- Set up pre-commit hook - 10 minutes  
- Add GitHub Actions check - 15 minutes
- **Total: ~45 minutes, one-time setup**

---

## Quick Implementation Checklist

```bash
# 1. Create sync script
cat > scripts/sync-version.py << 'EOF'
[script content from Solution 2]
EOF

# 2. Test it
python scripts/sync-version.py

# 3. Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
python scripts/sync-version.py
EOF
chmod +x .git/hooks/pre-commit

# 4. Future updates - just update pom.xml
vim pom.xml  # Change version
python scripts/sync-version.py  # Auto-sync all files
git add .
git commit -m "Bump version to X.Y.Z"
```

---

## Long-Term Considerations

For v2.0, consider:

1. **Maven Release Plugin** - Automates version bumping and tagging
   ```bash
   mvn release:prepare release:perform
   ```

2. **Semantic Versioning** - Enforce via commitlint + GitHub Actions

3. **Changelog automation** - Keep CHANGELOG.md automatically updated via conventional commits

4. **Docker image tags** - Version synchronized with container registry

---

**Recommendation**: Implement Solution 2 (Python script) now for immediate relief, then evolve to Maven plugin approach when building v2.0 infrastructure.

