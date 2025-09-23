# GhidraMCP Requirements Management

## 📦 Installation Guide

### **Production Use**
```bash
# Core dependencies only
pip install -r requirements.txt
```

### **Development & Testing**
```bash
# Production dependencies + comprehensive test suite
pip install -r requirements.txt
pip install -r requirements-test.txt
```

### **Quick Setup**
```bash
# All-in-one installation for development
pip install -r requirements.txt && pip install -r requirements-test.txt
```

## 📋 Requirements Files Overview

### **`requirements.txt`** - Production Dependencies
- **Purpose**: Core runtime dependencies for GhidraMCP server
- **Contents**: 
  - `mcp>=1.5.0,<2.0.0` - MCP server framework
  - `requests>=2.28.0,<3.0.0` - HTTP client library
- **Usage**: Install for production deployment or minimal functionality

### **`requirements-test.txt`** - Comprehensive Test Suite
- **Purpose**: All dependencies needed for running the complete test suite
- **Contents**:
  - **Testing Framework**: pytest, pytest-cov, pytest-html, pytest-xdist
  - **HTTP Testing**: requests-mock, responses
  - **Performance**: pytest-benchmark
  - **Development**: black, flake8, isort, mypy
  - **Async Support**: pytest-asyncio, aiohttp (for future SSE testing)
- **Usage**: Install for development, testing, or CI/CD pipelines

## 🔧 Best Practices

### **Dependency Management**
1. **Pin major versions** with flexibility for minor updates
2. **Separate production from development** dependencies
3. **Regular updates** with testing to ensure compatibility
4. **Version ranges** to allow security patches

### **Installation Order**
1. **Always install production requirements first**
2. **Add test requirements for development**
3. **Use virtual environments** to isolate dependencies

### **CI/CD Integration**
```yaml
# Example GitHub Actions step
- name: Install dependencies
  run: |
    pip install -r requirements.txt
    pip install -r requirements-test.txt
```

## 🧪 Testing Dependencies Verified

All test requirements have been verified against the current test suite:

### **Core Testing** ✅
- `pytest>=7.0.0` - Main testing framework
- `requests-mock>=1.10.0` - HTTP mocking for API tests
- `unittest.mock` - Built-in mocking utilities

### **Advanced Testing** ✅
- `pytest-benchmark>=4.0.0` - Performance testing
- `pytest-cov>=4.0.0` - Coverage analysis
- `threading`, `queue` - Concurrent testing support

### **Development Tools** ✅
- `black>=22.0.0` - Code formatting
- `flake8>=5.0.0` - Code linting
- `mypy>=1.0.0` - Type checking

## 🚀 Quick Verification

```bash
# Verify installation
python -c "import pytest, requests, mcp; print('All core dependencies working!')"

# Run tests to verify complete setup
python -m pytest tests/ -v
```

## 📊 Dependencies Summary

| Category | Production | Testing | Total |
|----------|-----------|---------|-------|
| **Core** | 2 | 15+ | 17+ |
| **Optional** | 0 | 10+ | 10+ |
| **Built-in** | 5+ | 5+ | 10+ |

**Status**: ✅ **Ready for production and development use**