# Ghidra MCP Development Guide

**Version:** 1.2.0  
**Updated:** September 23, 2025  
**Package:** com.xebyte

## 🏁 Quick Start for Developers

### Prerequisites

- **Java 21 LTS** (OpenJDK recommended)
- **Apache Maven 3.9+** 
- **Ghidra 11.4.2** (or compatible version)
- **Python 3.8+** with pip
- **Git** for version control

### Environment Setup

1. **Clone and Setup Repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Install Python Dependencies:**
   ```bash
   # Production dependencies
   pip install -r requirements.txt
   
   # Development and testing dependencies
   pip install -r requirements-test.txt
   ```

3. **Copy Ghidra Libraries:**
   ```bash
   # Windows (PowerShell)
   .\copy-ghidra-libs.bat "C:\path\to\ghidra"
   ```

4. **Build and Test:**
   ```bash
   # Build the plugin
   mvn clean package assembly:single
   
   # Run comprehensive tests
   python -m pytest
   ```

## 🔨 Build Process

### Maven Build Commands

```bash
# Full build with tests
mvn clean package assembly:single

# Quick build (skip tests)
mvn clean package assembly:single -DskipTests

# Run only tests
mvn test
```

### Build Outputs

- `target/GhidraMCP-1.2.0.zip` - Ghidra extension package
- `target/GhidraMCP.jar` - Main plugin JAR  
- Test reports in `target/surefire-reports/`

## 🧪 Testing Strategy

### Test Architecture

```
tests/
├── unit/          # 66 tests - Core functionality 
├── integration/   # 73 tests - API endpoints
├── functional/    # 19 tests - End-to-end workflows
├── fixtures/      # Test helpers and mock data
└── conftest.py    # Pytest configuration
```

### Running Tests

```bash
# All tests (158 total)
python -m pytest

# By category
python -m pytest tests/unit/         # Unit tests
python -m pytest tests/integration/  # Integration tests
python -m pytest tests/functional/   # Functional tests

# With coverage
python -m pytest --cov=src --cov-report=html

# Verbose output
python -m pytest -v
```

### Test Status
- **Total:** 158 tests
- **Passing:** 147 (100% success rate)
- **Skipped:** 11 (when dependencies unavailable)

## 🛠️ Development Workflow

### Standard Development Process

1. **Create Feature Branch:**
   ```bash
   git checkout -b feature/your-feature
   ```

2. **Make Changes:**
   - Java code: `src/main/java/com/xebyte/`
   - Python code: root directory
   - Tests: `tests/` subdirectories

3. **Test Changes:**
   ```bash
   python -m pytest tests/unit/ -v
   mvn clean test
   ```

4. **Build and Verify:**
   ```bash
   mvn clean package assembly:single
   ```

5. **Commit:**
   ```bash
   git add .
   git commit -m "feat: description of changes"
   git push origin feature/your-feature
   ```

## 📝 Code Standards

### Java (com.xebyte package)
- Follow standard Java conventions
- Use Ghidra APIs appropriately
- Implement robust error handling
- Document complex logic

### Python
- PEP 8 compliant
- Type hints for all functions
- Comprehensive docstrings
- Graceful error handling

## 🚀 MCP Tools Development

### Adding New Tools

1. **Python Tool Function:**
   ```python
   @mcp.tool()
   def new_analysis_tool(address: str, depth: int = 1) -> list:
       """
       Perform new type of analysis.
       
       Args:
           address: Memory address to analyze
           depth: Analysis depth level
           
       Returns:
           Analysis results as list
       """
       return safe_get("new_endpoint", {"address": address, "depth": depth})
   ```

2. **Java Endpoint (if needed):**
   ```java
   @GetMapping("/new_endpoint")
   @ResponseBody
   public List<String> newEndpoint(@RequestParam String address, 
                                  @RequestParam(defaultValue = "1") int depth) {
       // Implementation
   }
   ```

3. **Add Tests:**
   ```python
   def test_new_analysis_tool(self, api_client):
       result = api_client.new_analysis_tool("0x401000", 2)
       assert result is not None
   ```

## 🔍 Debugging

### Python Debugging
```bash
# Debug mode
python -v bridge_mcp_ghidra.py

# Pytest debugging  
python -m pytest --pdb tests/path/to/test.py
```

### Java Debugging
```bash
# Maven debug output
mvn -X clean test

# Specific test
mvn test -Dtest=GhidraMCPPluginTest
```

## 📊 Performance & Quality

### Current Metrics
- **MCP Tools:** 57 available
- **Response Time:** Sub-second for most operations
- **Test Success:** 100% (147/147 passing)
- **Documentation:** Complete API coverage

### Performance Testing
Tests include response time validation:
```python
def test_performance(self, api_client):
    start = time.time()
    response = api_client.list_functions(limit=100)
    duration = time.time() - start
    assert duration < 1.0  # Must respond within 1 second
```

## 🤝 Contributing

### Pull Request Requirements
- [ ] All 158 tests pass
- [ ] Code follows established standards  
- [ ] Documentation updated
- [ ] Performance impact assessed
- [ ] Backward compatibility maintained

### Review Process
1. Fork repository and create feature branch
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit PR with clear description

## 📚 Documentation Files

- **[API_REFERENCE.md](API_REFERENCE.md)** - Complete MCP tools documentation (57 tools)
- **[REQUIREMENTS.md](REQUIREMENTS.md)** - Dependency management guide
- **[DATA_TYPE_TOOLS.md](DATA_TYPE_TOOLS.md)** - Advanced data analysis tools
- **[../tests/README.md](../tests/README.md)** - Testing framework details

## 🏆 Quality Assurance

### Automated Checks
- **Build Verification:** Maven builds must succeed
- **Test Coverage:** All new code must include tests
- **Documentation:** API changes must update documentation
- **Performance:** Response times must remain optimal

### Release Process
1. Version bump in `pom.xml`
2. Full test suite execution (158 tests)
3. Documentation updates
4. Build verification
5. Git tag and release

---

**Production-ready development environment with comprehensive testing and quality assurance.**
