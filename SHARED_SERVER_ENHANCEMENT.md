# Enhancement: Shared Ghidra Server Support

## Overview

Add the ability for ghidra-mcp headless server to connect to a shared Ghidra repository server, enabling centralized analysis storage and team collaboration.

## Current State

- ghidra-mcp works with local projects only
- Analysis is stored in container-local volume
- No integration with shared Ghidra server

## Target State

- ghidra-mcp connects to shared Ghidra server (ghidra-server:13100)
- All analysis stored in shared repository
- Service account for automation tracking
- Checkout/checkin workflow for file editing

## Architecture

```
┌─────────────────┐      ┌─────────────────┐
│  ghidra-mcp     │      │  ghidra-server  │
│  (headless)     │◄────►│  (shared repo)  │
│  port 8089      │      │  port 13100     │
└─────────────────┘      └─────────────────┘
        │                         │
        │                         │
   MCP/REST API            pd2 repository
   (Claude, etc.)          (all analysis)
```

## Configuration

### Environment Variables
```bash
# Server connection
GHIDRA_SERVER_HOST=ghidra-server
GHIDRA_SERVER_PORT=13100
GHIDRA_SERVER_USER=ghidra-mcp

# Repository settings
GHIDRA_DEFAULT_REPOSITORY=pd2
GHIDRA_AUTO_CHECKOUT=true
```

### Service Account
- **Username:** ghidra-mcp
- **Repository:** pd2 (admin access)
- **Created:** 2026-02-21

## New Endpoints

### Server Connection
```
POST /server/connect
  Connect to the configured Ghidra server
  
GET /server/status
  Check server connection status
  
POST /server/disconnect
  Disconnect from server
```

### Repository Operations
```
GET /server/repositories
  List available repositories
  
GET /server/repository/{name}/files
  List files in repository (with optional path filter)
  
GET /server/repository/{name}/file/{path}
  Get file info (version, checkout status, etc.)
```

### Checkout/Checkin Workflow
```
POST /server/checkout
  {
    "repository": "pd2",
    "path": "/Classic/1.00/D2Game.dll",
    "exclusive": false
  }
  Check out a file for editing

POST /server/checkin
  {
    "repository": "pd2",
    "path": "/Classic/1.00/D2Game.dll",
    "comment": "Added function analysis"
  }
  Check in changes with comment
  
POST /server/cancel-checkout
  Cancel a checkout without saving changes
```

### Program Operations (Enhanced)
```
POST /program/open-shared
  {
    "repository": "pd2",
    "path": "/Classic/1.00/D2Game.dll"
  }
  Open a program from shared repository (auto-checkout)
  
POST /program/save-shared
  Save current program to shared repository (auto-checkin)
```

## Implementation Plan

### Phase 1: Server Connection (2-3 days)
- [ ] Add server connection configuration
- [ ] Implement RepositoryServerAdapter connection
- [ ] Add /server/connect and /server/status endpoints
- [ ] Connection health monitoring

### Phase 2: Repository Browsing (1-2 days)
- [ ] List repositories
- [ ] Browse repository contents
- [ ] Get file metadata

### Phase 3: Checkout/Checkin (2-3 days)
- [ ] Implement checkout workflow
- [ ] Implement checkin workflow
- [ ] Handle conflicts and locking
- [ ] Add checkout/checkin endpoints

### Phase 4: Integration (1-2 days)
- [ ] Modify /program/open to support shared paths
- [ ] Auto-checkout on open
- [ ] Auto-checkin on save
- [ ] Update Docker configuration

## Ghidra APIs to Use

```java
// Server connection
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryServerAdapter;

// Repository operations
RepositoryServerAdapter server = ClientUtil.getRepositoryServer(host, port);
RepositoryAdapter repo = server.getRepository("pd2");

// Checkout/checkin
DomainFile file = repo.getFile("/Classic/1.00/D2Game.dll");
file.checkout(CheckoutType.EXCLUSIVE, monitor);
// ... make changes ...
file.checkin(comment, monitor);
```

## Docker Compose Changes

```yaml
ghidra-mcp:
  environment:
    - GHIDRA_SERVER_HOST=ghidra-server
    - GHIDRA_SERVER_PORT=13100
    - GHIDRA_SERVER_USER=ghidra-mcp
    - GHIDRA_DEFAULT_REPOSITORY=pd2
  depends_on:
    - ghidra-server
```

## Testing

- [ ] Connect to server
- [ ] List repositories
- [ ] Browse pd2 repository
- [ ] Checkout file
- [ ] Make analysis changes via existing endpoints
- [ ] Checkin changes
- [ ] Verify changes visible in Ghidra GUI

## Success Criteria

1. ghidra-mcp can connect to ghidra-server
2. Files can be checked out and checked in
3. Analysis changes persist in shared repository
4. Changes visible when opening same file in Ghidra GUI
5. Audit trail shows "ghidra-mcp" as author

---

*Created: February 21, 2026*
*Status: Planning*
