# Release Workflows Documentation

This directory contains GitHub Actions workflows for automated building, testing, and releasing of GhidraMCP.

## 📋 Available Workflows

### 1. `build.yml` - Continuous Integration

**Triggers:** Push to main, Pull Requests

- Builds the project with Maven
- Downloads required Ghidra libraries
- Runs all tests
- Creates build artifacts

### 2. `release.yml` - Manual/Tagged Releases

**Triggers:**

- Git tags matching `v*.*.*` (e.g., `v1.2.0`)
- Manual trigger via GitHub Actions UI

**Features:**

- Full build and test execution
- Comprehensive release artifact preparation
- Automatic GitHub release creation
- Professional release notes generation
- Installation instructions included

### 3. `auto-release.yml` - Automatic Version Releases

**Triggers:** Version changes in `pom.xml` on main branch

**Features:**

- Detects version bumps in pom.xml
- Automatically creates and pushes tags
- Builds and releases without manual intervention
- Generates changelog from commits

### 4. `pre-release.yml` - Development Pre-Releases

**Triggers:** Manual trigger only

**Features:**

- Creates pre-release versions from any branch
- Validates pre-release version format
- Marks releases as pre-release in GitHub
- Includes testing warnings and feedback instructions

## 🚀 How to Create a Release

### Option 1: Manual Release (Recommended)

1. **Via Git Tag:**

   ```bash
   git tag -a v1.2.0 -m "Release version 1.2.0"
   git push origin v1.2.0
   ```

2. **Via GitHub Actions UI:**
   - Go to Actions → "Create Release"
   - Click "Run workflow"
   - Enter version (e.g., "1.2.0")
   - Choose whether to create a tag
   - Click "Run workflow"

### Option 2: Automatic Release

1. **Update version in pom.xml:**

   ```xml
   <version>1.3.0</version>
   ```

2. **Commit and push to main:**

   ```bash
   git add pom.xml
   git commit -m "bump version to 1.3.0"
   git push origin main
   ```

3. **Release is created automatically!**

### Option 3: Pre-Release for Testing

1. **Via GitHub Actions UI:**
   - Go to Actions → "Create Pre-Release"
   - Click "Run workflow"
   - Enter pre-release version (e.g., "1.3.0-beta.1")
   - Select source branch
   - Click "Run workflow"

## 📦 Release Artifacts

Each release includes:
- **`GhidraMCP-{version}.zip`** - Main Ghidra plugin
- **`bridge_mcp_ghidra.py`** - MCP server with 222 tools via dynamic schema registration
- **`requirements.txt`** - Python dependencies
- **`README.md`** - Complete project documentation
- **`INSTALLATION.md`** - Quick installation guide
- **`LICENSE`** - License file (if present)

## 🔧 Technical Details

### Build Environment
- **OS:** Ubuntu Latest
- **Java:** OpenJDK 21 (Temurin)
- **Ghidra:** Version 12.0.3 (auto-downloaded)
- **Maven:** Latest stable version
- **Build Command:** `mvn clean package assembly:single`

### Required Libraries
All Ghidra libraries are automatically downloaded and configured:
- Base.jar, Decompiler.jar, Docking.jar
- Generic.jar, Project.jar, SoftwareModeling.jar
- Utility.jar, Gui.jar

### Quality Assurance
- **Automated CI validation** (offline Java tests, Python unit tests, build verification)
- **Build verification** before release creation
- **Artifact validation** and proper naming
- **Professional documentation** generation

## 🏷️ Version Format Guidelines

### Stable Releases
- **Format:** `X.Y.Z` (e.g., `1.2.0`)
- **Semantic Versioning:**
  - X = Major version (breaking changes)
  - Y = Minor version (new features)
  - Z = Patch version (bug fixes)

### Pre-Releases
- **Format:** `X.Y.Z-{type}.N` (e.g., `1.3.0-beta.1`)
- **Types:**
  - `alpha` - Early development version
  - `beta` - Feature-complete testing version
  - `rc` - Release candidate

## 🛠️ Workflow Maintenance

### Updating Ghidra Version
Update these variables in all workflow files:
```yaml
env:
  GHIDRA_VERSION: 12.0.3
  GHIDRA_DATE: 20250415
```

### Adding New Artifacts
Modify the "Prepare release artifacts" step in each workflow to include additional files.

### Customizing Release Notes
Edit the release notes generation sections to include project-specific information.

## 🔍 Troubleshooting

### Common Issues

**Build Failures:**
- Check Java version compatibility
- Verify Ghidra library downloads
- Review Maven configuration

**Tag Creation Issues:**
- Ensure proper permissions
- Check for existing tags
- Verify version format

**Release Upload Problems:**
- Confirm GitHub token permissions
- Check artifact file sizes
- Verify file paths

### Debug Information
Each workflow provides:
- **Step-by-step logs** for troubleshooting
- **Artifact listings** for verification
- **Build summaries** in GitHub Actions UI
- **Release links** for easy access

## 📊 Workflow Status

| Workflow | Status | Purpose | Frequency |
|----------|--------|---------|-----------|
| Build | ✅ Active | CI/CD | Every push/PR |
| Release | ✅ Active | Stable releases | Manual/Tagged |
| Auto-Release | ✅ Active | Version bump releases | Automatic |
| Pre-Release | ✅ Active | Testing releases | Manual |

---

**For support with release workflows, please check the GitHub Actions logs or create an issue in the repository.**
