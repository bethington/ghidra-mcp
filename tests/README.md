# GhidraMCP Test Suite

A comprehensive, production-ready test suite for the GhidraMCP project following industry best practices.

## 🏗️ Test Architecture

The test suite is organized into three distinct categories following the **Test Pyramid** pattern:

```
tests/
├── unit/           # Fast, isolated unit tests
├── integration/    # API endpoint integration tests  
├── functional/     # End-to-end workflow tests
├── fixtures/       # Shared test utilities and data
├── conftest.py     # Pytest configuration and fixtures
└── README.md       # This file
```

### Test Categories

| Category | Purpose | Speed | Dependencies | Coverage |
|----------|---------|-------|--------------|----------|
| **Unit** | Test individual components in isolation | Fast (< 1s) | None | High |
| **Integration** | Test API endpoints with Ghidra | Medium (1-10s) | Ghidra Server | Medium |
| **Functional** | Test complete workflows end-to-end | Slow (10s+) | Ghidra + Binary | Low |

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+** - Required for all tests
2. **Test Dependencies** - Install with:
   ```bash
   pip install -r requirements-test.txt
   ```
3. **Ghidra Server** - Required for integration and functional tests:
   - Start Ghidra with GhidraMCP plugin
   - Ensure server is running on `http://127.0.0.1:8089` (default)
   - Load a binary for functional tests

### Running Tests

#### Using the Test Runner (Recommended)
```bash
# Run all tests
python run_tests.py

# Run specific test categories
python run_tests.py --unit           # Unit tests only
python run_tests.py --integration    # Integration tests only  
python run_tests.py --functional     # Functional tests only

# Advanced options
python run_tests.py --coverage       # Generate coverage report
python run_tests.py --html           # Generate HTML report
python run_tests.py --slow           # Include slow tests
python run_tests.py --parallel 4     # Run with 4 parallel workers
python run_tests.py --server-url http://localhost:8080/  # Custom server URL
```

#### Using pytest directly
```bash
# All tests
pytest tests/

# Specific categories
pytest tests/unit/                   # Unit tests
pytest tests/integration/            # Integration tests
pytest tests/functional/             # Functional tests

# With markers
pytest -m "unit"                     # Unit tests only
pytest -m "integration"              # Integration tests only
pytest -m "functional"               # Functional tests only
pytest -m "not slow"                 # Skip slow tests

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## 📋 Test Organization

### Unit Tests (`tests/unit/`)
- **Purpose**: Test individual components in isolation
- **Dependencies**: None (uses mocking)
- **Speed**: Very fast (< 1 second each)
- **Examples**:
  - API client initialization
  - Configuration validation
  - Utility functions
  - Data validation

### Integration Tests (`tests/integration/`)
- **Purpose**: Test API endpoints with real Ghidra instance
- **Dependencies**: Running Ghidra server
- **Speed**: Medium (1-10 seconds each)
- **Examples**:
  - REST endpoint responses
  - Data type operations
  - Function analysis
  - Error handling

### Functional Tests (`tests/functional/`)
- **Purpose**: Test complete workflows end-to-end
- **Dependencies**: Ghidra server + loaded binary
- **Speed**: Slow (10+ seconds each)
- **Examples**:
  - Binary analysis workflow
  - Data type management workflow
  - Call graph analysis
  - Documentation generation
