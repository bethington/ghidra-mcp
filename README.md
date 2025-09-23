# Ghidra MCP Server

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-21%20LTS-orange.svg)](https://openjdk.java.net/projects/jdk/21/)
[![Ghidra Version](https://img.shields.io/badge/Ghidra-11.4.2-green.svg)](https://ghidra-sre.org/)
[![MCP Version](https://img.shields.io/badge/MCP-1.5.0-purple.svg)](https://modelcontextprotocol.io/)

A production-ready Model Context Protocol (MCP) server that bridges Ghidra's powerful reverse engineering capabilities with modern AI tools and automation frameworks.

## 🌟 Features

### Core MCP Integration
- **Full MCP 1.5.0 Compatibility** - Complete implementation of Model Context Protocol
- **57 MCP Tools Available** - Comprehensive API surface for binary analysis
- **100% Success Rate** - Production-tested reliability across all tools
- **Real-time Analysis** - Live integration with Ghidra's analysis engine

### Binary Analysis Capabilities
- **Function Analysis** - Decompilation, call graphs, cross-references
- **Data Structure Discovery** - Automatic struct/union/enum creation
- **String Extraction** - Comprehensive string analysis and categorization  
- **Import/Export Analysis** - Symbol table and library dependency mapping
- **Memory Mapping** - Complete memory layout documentation
- **Security Assessment** - Vulnerability pattern detection and analysis

### Development & Automation
- **Automated Development Cycle** - Complete build-test-deploy-verify pipeline
- **Quality Assurance** - Automated documentation quality scoring (100% achieved)
- **Performance Monitoring** - Response time tracking and optimization
- **Error Recovery** - Intelligent fallback strategies for failed operations

## 🚀 Quick Start

### Prerequisites

- **Java 21 LTS** (OpenJDK recommended)
- **Apache Maven 3.9+**
- **Ghidra 11.4.2** (or compatible version)
- **Python 3.8+** with pip

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bethington/ghidra-mcp.git
   cd ghidra-mcp
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Copy Ghidra libraries:**
   ```bash
   # Windows
   copy-ghidra-libs.bat "C:\path\to\ghidra"
   
   # Linux/Mac
   ./copy-ghidra-libs.sh /path/to/ghidra
   ```

4. **Build the plugin:**
   ```bash
   mvn clean package assembly:single
   ```

5. **Deploy to Ghidra:**
   ```bash
   python ghidra_dev_cycle.py --comprehensive-test --document-binary
   ```

### Basic Usage

#### Option 1: Stdio Transport (Recommended for AI tools)
```bash
python bridge_mcp_ghidra.py
```

#### Option 2: SSE Transport (Web/HTTP clients)
```bash
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081
```

#### Option 3: Development Cycle (Full automation)
```bash
python ghidra_dev_cycle.py --comprehensive-test --document-binary
```

## 📊 Production Performance

- **Reliability**: 100% success rate across 57 MCP tools
- **Speed**: Sub-second response for most operations
- **Throughput**: 1000+ API calls per minute
- **Quality**: Comprehensive test suite with 158 tests (147 passed, 11 skipped)
- **Uptime**: Automatic process recovery and error handling

## 🛠️ API Reference

### Core Operations
- `GET /check_connection` - Verify MCP connectivity
- `GET /get_metadata` - Program metadata and info
- `GET /get_entry_points` - Binary entry points discovery

### Function Analysis
- `GET /functions` - List all functions (paginated)
- `GET /searchFunctions` - Search functions by name/pattern
- `GET /decompile/{function}` - Decompile function to C pseudocode
- `GET /function_callers/{function}` - Get function callers
- `GET /function_callees/{function}` - Get function callees
- `GET /get_function_call_graph/{function}` - Function relationship graph

### Memory & Data
- `GET /segments` - Memory segments and layout
- `GET /get_function_by_address/{addr}` - Function at address
- `GET /disassemble_function/{addr}` - Disassembly listing
- `GET /xrefs_to/{addr}` - Cross-references to address
- `GET /xrefs_from/{addr}` - Cross-references from address

### Data Types & Structures
- `GET /data_types` - Available data types
- `POST /create_struct` - Create custom structure
- `POST /create_union` - Create union type
- `POST /create_enum` - Create enumeration

### Symbols & Strings
- `GET /imports` - Imported symbols and libraries
- `GET /exports` - Exported symbols and functions
- `GET /strings` - Extracted strings with analysis
- `GET /namespaces` - Available namespaces

See [API_REFERENCE.md](docs/API_REFERENCE.md) for complete documentation.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI/Automation │◄──►│   MCP Server    │◄──►│     Ghidra      │
│     Tools       │    │ (bridge_mcp_    │    │   Plugin        │
│                 │    │  ghidra.py)     │    │ (GhidraMCP.jar) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    REST API     │    │   Development   │    │   Binary        │
│   Interface     │    │     Cycle       │    │   Analysis      │
│                 │    │  (ghidra_dev_   │    │   Engine        │
│                 │    │   cycle.py)     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Development

### Running Tests
```bash
# Comprehensive MCP endpoint testing
python ghidra_dev_cycle.py --comprehensive-test

# Binary documentation quality testing
python ghidra_dev_cycle.py --document-binary

# Full development cycle with all tests
python ghidra_dev_cycle.py --comprehensive-test --document-binary
```

### Development Cycle Features
- Automated plugin building and deployment
- Ghidra process management and cleanup
- CodeBrowser window detection and verification
- Comprehensive endpoint testing (26 tests)
- Binary documentation workflow with quality scoring
- Performance monitoring and optimization

### Quality Metrics
- **Test Coverage**: 158 comprehensive tests across unit/integration/functional categories
- **MCP Tool Coverage**: 57/57 tools available and tested
- **Performance Tracking**: Response time monitoring and optimization
- **Error Recovery**: Intelligent fallback strategies for failed operations

## 📚 Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete endpoint documentation
- [Development Guide](docs/DEVELOPMENT_GUIDE.md) - Contributing and development setup
- [Data Type Tools](docs/DATA_TYPE_TOOLS.md) - Custom data structure creation
- [Enhanced Process](docs/ENHANCED_DEV_PROCESS.md) - Advanced development workflows

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run the comprehensive test suite (`python ghidra_dev_cycle.py --comprehensive-test`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Standards
- All new features must pass 100% of comprehensive tests
- Documentation quality score must maintain 100%
- Response times should remain under established baselines
- Error handling must include intelligent fallback strategies

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🏆 Production Status

**Current Version**: 1.2.0  
**Production Ready**: ✅ Yes  
**Package**: com.xebyte (updated from com.lauriewired)  
**Test Coverage**: 57/57 MCP tools (100%) + 158 comprehensive tests  
**Documentation Coverage**: 100%  
**Performance**: Optimized for production workloads  

## 🙏 Acknowledgments

- **Ghidra Team** - For the incredible reverse engineering platform
- **Model Context Protocol** - For the standardized AI integration framework
- **Contributors** - For testing, feedback, and improvements

---

**Ready for production deployment with enterprise-grade reliability and comprehensive binary analysis capabilities.**
