# Java Handler Refactoring Design

## Current State

The `GhidraMCPPlugin.java` file is **13,821 lines** with inline lambda handlers for 100+ endpoints. This makes maintenance difficult and testing challenging.

## Proposed Architecture

### 1. Base Handler Interface

```java
package com.xebyte.handlers;

import com.sun.net.httpserver.HttpExchange;
import ghidra.program.model.listing.Program;

/**
 * Base interface for all MCP endpoint handlers.
 */
public interface EndpointHandler {
    /**
     * Handle an HTTP request.
     * @param exchange The HTTP exchange
     * @param program The current program (may be null)
     */
    void handle(HttpExchange exchange, Program program) throws Exception;
    
    /**
     * Get the endpoint path (e.g., "/list_functions")
     */
    String getPath();
    
    /**
     * Get the HTTP method (GET, POST, etc.)
     */
    default String getMethod() {
        return "GET";
    }
}
```

### 2. Abstract Base Handler

```java
package com.xebyte.handlers;

public abstract class AbstractHandler implements EndpointHandler {
    
    protected void sendResponse(HttpExchange exchange, int code, String response) {
        // Common response logic
    }
    
    protected Map<String, String> parseQueryParams(String query) {
        // Common query parsing
    }
    
    protected String escapeJson(String s) {
        // Common JSON escaping
    }
    
    protected Address parseAddress(Program program, String addressStr) {
        // Common address parsing
    }
}
```

### 3. Domain-Specific Handler Groups

| Package | Responsibility | Example Endpoints |
|---------|---------------|-------------------|
| `handlers.functions` | Function operations | list_functions, rename_function, decompile_function |
| `handlers.data` | Data item operations | list_data_items, rename_data, apply_data_type |
| `handlers.analysis` | Analysis operations | analyze_function_completeness, detect_array_bounds |
| `handlers.comments` | Comment operations | set_plate_comment, set_decompiler_comment |
| `handlers.labels` | Label operations | create_label, delete_label, rename_label |
| `handlers.types` | Type operations | create_struct, list_data_types |
| `handlers.xrefs` | Cross-reference operations | get_xrefs_to, get_xrefs_from |
| `handlers.scripts` | Script operations | run_script, list_scripts |
| `handlers.programs` | Program management | list_open_programs, switch_program |

### 4. Handler Registry

```java
package com.xebyte.handlers;

public class HandlerRegistry {
    private final Map<String, EndpointHandler> handlers = new HashMap<>();
    
    public void register(EndpointHandler handler) {
        handlers.put(handler.getPath(), handler);
    }
    
    public void registerAll(HttpServer server) {
        for (EndpointHandler handler : handlers.values()) {
            server.createContext(handler.getPath(), exchange -> {
                handler.handle(exchange, currentProgram);
            });
        }
    }
}
```

### 5. Example Handler Implementation

```java
package com.xebyte.handlers.functions;

public class ListFunctionsHandler extends AbstractHandler {
    
    @Override
    public String getPath() {
        return "/list_functions";
    }
    
    @Override
    public void handle(HttpExchange exchange, Program program) {
        if (program == null) {
            sendResponse(exchange, 400, "No program loaded");
            return;
        }
        
        Map<String, String> params = parseQueryParams(exchange);
        int offset = parseIntOrDefault(params.get("offset"), 0);
        int limit = parseIntOrDefault(params.get("limit"), 100);
        
        List<Function> functions = getFunctions(program, offset, limit);
        String json = formatFunctionsJson(functions);
        
        sendResponse(exchange, 200, json);
    }
}
```

## Migration Strategy

### Phase 1: Create Infrastructure (Low Risk)
1. Create handler interfaces and abstract base class
2. Create HandlerRegistry
3. Create utility classes for common operations

### Phase 2: Migrate Read-Only Endpoints (Medium Risk)
1. Start with simple GET endpoints (list_functions, list_data_items)
2. Keep original inline handlers as fallback
3. Test extensively before removing old code

### Phase 3: Migrate Write Endpoints (Higher Risk)
1. Migrate rename operations
2. Migrate comment operations  
3. Migrate type operations

### Phase 4: Remove Old Code
1. Remove inline lambdas
2. Clean up GhidraMCPPlugin.java
3. Final testing

## Testing Considerations

With handlers extracted, we can:
1. Mock Program and test handler logic
2. Create unit tests for each handler
3. Test response formatting independently
4. Test error handling paths

## Benefits

| Before | After |
|--------|-------|
| 13,821 lines in one file | ~500 lines per handler file |
| Hard to test | Unit testable |
| Hard to find code | Organized by domain |
| Duplicate logic | Shared base class |
| No separation of concerns | Clean architecture |

## Estimated Effort

- Phase 1: 2-4 hours
- Phase 2: 4-8 hours  
- Phase 3: 8-16 hours
- Phase 4: 2-4 hours
- Testing: Throughout

Total: **16-32 hours** of focused development time

## Recommendation

This refactoring should be done incrementally over multiple sessions, with thorough testing at each phase. The current monolithic structure works but will become increasingly difficult to maintain as more endpoints are added.
