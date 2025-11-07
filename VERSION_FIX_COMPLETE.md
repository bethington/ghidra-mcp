# Version Management - Preventing Future Version Mismatches

## Problem
The build previously showed version 1.2.0 instead of 1.9.2 due to hardcoded version references in scripts.

## Solution Implemented

### 1. Dynamic Version Configuration ✅

**pom.xml** (Source of Truth)
```xml
<version>1.9.2</version>
```

**extension.properties** (Dynamic)
```properties
version=${project.version}
```

**Assembly Plugin** (Dynamic)
```xml
<finalName>GhidraMCP-${project.version}</finalName>
```

All build artifacts automatically use the version from pom.xml.

### 2. Fixed Hardcoded References ✅

**Updated:**
- `scripts/ghidra_plugin_deployment_verifier.py` - Changed from 1.2.0 to 1.9.2

### 3. Version Verification Script ✅

**Created:** `scripts/verify_version.py`

Automatically verifies:
- ✅ pom.xml version is valid
- ✅ extension.properties uses dynamic versioning
- ✅ Script references match pom.xml version
- ⚠️ Warns about any hardcoded version references

**Usage:**
```bash
python scripts/verify_version.py
```

**Output:**
```
============================================================
GhidraMCP Version Verification
============================================================

✅ pom.xml version: 1.9.2
✅ extension.properties: Uses ${project.version} (dynamic)

Checking for hardcoded version references...
⚠️  WARNING: Found hardcoded version references:
   - deployment_verifier.py references version 1.9.2

These should reference pom.xml version: 1.9.2
✅ All hardcoded versions match pom.xml

============================================================
✅ Version Verification Complete - Version: 1.9.2
============================================================

Build will create:
   - target/GhidraMCP-1.9.2.zip
   - target/GhidraMCP.jar
```

### 4. Automated Pre-Build Check ✅

**Updated:** `.vscode/tasks.json`

The "Build Ghidra Plugin" task now depends on "Verify Version Consistency":
```json
{
    "label": "Build Ghidra Plugin",
    "dependsOn": ["Verify Version Consistency"]
}
```

**Benefit:** Version verification runs automatically before every build.

## How to Update Version in Future

### Single Source of Truth: pom.xml

**To release version 1.9.3:**

1. **Update pom.xml:**
   ```xml
   <version>1.9.3</version>
   ```

2. **Run verification:**
   ```bash
   python scripts/verify_version.py
   ```

3. **Update any hardcoded references** (if script finds them):
   ```bash
   # Example: deployment verifier
   vim scripts/ghidra_plugin_deployment_verifier.py
   # Change GhidraMCP-1.9.2.zip to GhidraMCP-1.9.3.zip
   ```

4. **Build:**
   ```bash
   mvn clean package assembly:single
   ```

5. **Verify artifacts:**
   ```bash
   ls target/GhidraMCP-1.9.3.zip
   ```

### What Gets Updated Automatically

✅ **Automatic (Maven handles):**
- `target/GhidraMCP-X.Y.Z.zip` filename
- `extension.properties` version field
- `GhidraMCP.jar` manifest version

❌ **Manual (if needed):**
- Script references (deployment_verifier.py)
- Documentation version numbers
- GitHub release tags

## Verification Checklist

Before releasing a new version:

- [ ] Update `pom.xml` version
- [ ] Run `python scripts/verify_version.py`
- [ ] Fix any warnings from verification script
- [ ] Build: `mvn clean package assembly:single`
- [ ] Verify ZIP filename: `ls target/GhidraMCP-*.zip`
- [ ] Test deployment: `.\deploy-to-ghidra.ps1`
- [ ] Verify Ghidra shows correct version

## Files That Reference Version

### Dynamic (Auto-updated by Maven)
- `extension.properties` → `${project.version}`
- `target/GhidraMCP-X.Y.Z.zip` → From pom.xml
- `Module.manifest` → From extension.properties

### Hardcoded (Need manual update)
- `scripts/ghidra_plugin_deployment_verifier.py` → Line 72
- Documentation files (historical references only)

## Testing

```bash
# 1. Verify version
python scripts/verify_version.py

# 2. Build
mvn clean package assembly:single -DskipTests

# 3. Check artifacts
ls -la target/GhidraMCP-*.zip

# 4. Deploy
.\deploy-to-ghidra.ps1

# 5. Verify in Ghidra
# File > Configure > Miscellaneous > GhidraMCP
# Should show: "Version: 1.9.2"
```

## Summary

✅ **Fixed:** Version now consistently shows as 1.9.2
✅ **Prevented:** Added verification script to catch future mismatches
✅ **Automated:** Build task runs verification automatically
✅ **Documented:** Clear process for updating versions

**No more 1.2.0 issues!** The version system is now robust and maintainable.
