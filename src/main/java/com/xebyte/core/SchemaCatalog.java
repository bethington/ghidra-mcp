package com.xebyte.core;

import com.google.gson.Gson;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the documented MCP schema for GUI and headless modes.
 *
 * <p>The runtime server can expose more raw HTTP contexts than the documented MCP
 * surface. This catalog merges annotation-scanned service tools with the manual
 * mode-specific endpoints that are intentionally part of the published schema.
 */
public final class SchemaCatalog {

    private static final String MANUAL_ENDPOINTS_RESOURCE = "/manual-endpoints.json";
    private static final Gson GSON = new Gson();
    private static final List<ManualToolConfig> MANUAL_TOOLS = loadManualTools();

    private SchemaCatalog() {}

    public enum RuntimeMode {
        GUI("gui"),
        HEADLESS("headless");

        private final String jsonValue;

        RuntimeMode(String jsonValue) {
            this.jsonValue = jsonValue;
        }

        public String jsonValue() {
            return jsonValue;
        }
    }

    public static String generateSchema(AnnotationScanner scanner, RuntimeMode mode) {
        List<AnnotationScanner.ToolDescriptor> descriptors = buildDescriptors(scanner, mode);
        StringBuilder sb = new StringBuilder();
        sb.append("{\"tools\": [");
        for (int i = 0; i < descriptors.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(descriptors.get(i).toJson());
        }
        sb.append("], \"count\": ").append(descriptors.size()).append("}");
        return sb.toString();
    }

    public static int countTools(AnnotationScanner scanner, RuntimeMode mode) {
        return buildDescriptors(scanner, mode).size();
    }

    private static List<AnnotationScanner.ToolDescriptor> buildDescriptors(
            AnnotationScanner scanner, RuntimeMode mode) {
        List<AnnotationScanner.ToolDescriptor> descriptors = new ArrayList<>(scanner.getDescriptors());
        for (ManualToolConfig tool : MANUAL_TOOLS) {
            if (tool.supports(mode)) {
                descriptors.add(tool.toDescriptor());
            }
        }
        descriptors.sort(Comparator.comparing(AnnotationScanner.ToolDescriptor::path));
        return descriptors;
    }

    private static List<ManualToolConfig> loadManualTools() {
        try (InputStream input = SchemaCatalog.class.getResourceAsStream(MANUAL_ENDPOINTS_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("Missing schema resource: " + MANUAL_ENDPOINTS_RESOURCE);
            }
            try (InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
                ManualToolConfig[] configs = GSON.fromJson(reader, ManualToolConfig[].class);
                if (configs == null) {
                    return List.of();
                }
                return List.of(configs);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load schema resource: " + MANUAL_ENDPOINTS_RESOURCE, e);
        }
    }

    private static final class ManualToolConfig {
        String path;
        String method;
        String description;
        String category;
        String categoryDescription;
        List<ManualParamConfig> params;
        List<String> modes;

        boolean supports(RuntimeMode mode) {
            return modes != null && modes.contains(mode.jsonValue());
        }

        AnnotationScanner.ToolDescriptor toDescriptor() {
            List<AnnotationScanner.ParamDescriptor> descriptors = new ArrayList<>();
            if (params != null) {
                for (ManualParamConfig param : params) {
                    descriptors.add(param.toDescriptor());
                }
            }
            return new AnnotationScanner.ToolDescriptor(
                    path,
                    method,
                    description != null ? description : "",
                    category != null ? category : "",
                    categoryDescription != null ? categoryDescription : "",
                    descriptors);
        }
    }

    private static final class ManualParamConfig {
        String name;
        String type;
        String source;
        Boolean required;
        String defaultValue;
        String description;
        String paramType;

        AnnotationScanner.ParamDescriptor toDescriptor() {
            return new AnnotationScanner.ParamDescriptor(
                    name,
                    type != null ? type : "string",
                    source != null ? source : "query",
                    required == null ? true : !required,
                    defaultValue,
                    description != null ? description : "",
                    paramType != null ? paramType : ""
            );
        }
    }
}
