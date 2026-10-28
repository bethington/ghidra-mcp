package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

import java.math.BigInteger;
import java.util.*;

/** Equate selection, validation and mutation share the server's write lock and transaction. */
final class EquateService {
    private final ThreadingStrategy threading;

    EquateService(ThreadingStrategy threading) {
        this.threading = Objects.requireNonNull(threading);
    }

    Response list(Program program, String valueText, String nameContains, Address address,
                  boolean includeReferences, int offset, int limit) {
        try {
            Long value = parseValue(valueText);
            return threading.executeRead(() -> {
                List<Map<String, Object>> items = new ArrayList<>();
                for (Equate eq : definitions(program.getEquateTable())) {
                    if (value != null && eq.getValue() != value) continue;
                    if (present(nameContains) && !eq.getName().toLowerCase(Locale.ROOT)
                            .contains(nameContains.strip().toLowerCase(Locale.ROOT))) continue;
                    List<Map<String, Object>> refs = new ArrayList<>();
                    if (includeReferences || address != null) {
                        for (EquateReference ref : references(eq)) {
                            if (address == null || address.equals(ref.getAddress())) {
                                refs.add(referenceMap(ref));
                            }
                        }
                        if (address != null && refs.isEmpty()) continue;
                    }
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("name", eq.getName());
                    item.put("value", eq.getValue());
                    item.put("display_value", eq.getDisplayValue());
                    item.put("reference_count", eq.getReferenceCount());
                    item.put("enum_based", eq.isEnumBased());
                    if (includeReferences || address != null) item.put("references", refs);
                    items.add(item);
                }
                int from = Math.min(items.size(), Math.max(0, offset));
                int to = limit <= 0 ? items.size() : (int) Math.min(items.size(), (long) from + limit);
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("kind", "equates");
                out.put("items", new ArrayList<>(items.subList(from, to)));
                out.put("count", to - from);
                out.put("total", items.size());
                out.put("offset", Math.max(0, offset));
                if (limit > 0) out.put("limit", limit);
                return Response.ok(out);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    Response set(Program program, String action, String name, String valueText, Address address,
                 int operandIndex, Function function, String newName, boolean deleteDefinition, int maxHits) {
        try {
            require(present(action), "action is required: apply | remove | rename");
            String operation = action.strip().toLowerCase(Locale.ROOT);
            require(Set.of("apply", "remove", "rename").contains(operation), "Unknown action: " + action);
            require(maxHits > 0, "max_hits must be positive");
            require(operandIndex >= -1, "operand_index must be -1 or nonnegative");
            require(address == null || function == null, "address and function_address are mutually exclusive");
            require(operandIndex == -1 || address != null || function != null,
                "operand_index requires address or function_address");
            Long value = parseValue(valueText);
            require("remove".equals(operation) || !deleteDefinition, "delete_definition requires action=remove");
            require("rename".equals(operation) || !present(newName), "new_name requires action=rename");
            // All program-dependent selection and validation belongs inside this callback.
            return threading.executeWrite(program, "set_equate " + operation, () -> switch (operation) {
                case "apply" -> apply(program, name, value, address, operandIndex, function, maxHits);
                case "remove" -> remove(program, name, value, address, operandIndex, function, deleteDefinition, maxHits);
                case "rename" -> {
                    require(address == null && function == null && operandIndex == -1 && value == null,
                        "rename accepts only name, new_name and max_hits");
                    yield rename(program, name, newName, maxHits);
                }
                default -> throw new AssertionError(operation);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    private Response apply(Program program, String name, Long value, Address address,
                           int operandIndex, Function function, int maxHits) throws Exception {
        require(present(name), "name is required");
        require(address != null || function != null, "address or function_address is required");
        List<Hit> hits = new ArrayList<>();
        for (Instruction ins : instructions(program, address, function, operandIndex)) {
            for (int i = 0; i < ins.getNumOperands(); i++) {
                if (operandIndex >= 0 && i != operandIndex) continue;
                Set<Long> seen = new HashSet<>();
                for (Object obj : ins.getOpObjects(i)) {
                    if (!(obj instanceof Scalar scalar)) continue;
                    if (value != null && !matches(scalar, value)) continue;
                    long selected = value != null ? value : scalar.getValue();
                    if (seen.add(selected)) hits.add(new Hit(ins.getAddress(), i, selected, scalar));
                }
            }
        }
        require(!hits.isEmpty(), "No scalar operand matched");
        require(hits.size() <= maxHits, "Refusing to modify " + hits.size() + " operands (max_hits=" + maxHits + ")");
        long selectedValue = hits.get(0).value();
        for (Hit hit : hits) require(hit.value() == selectedValue,
            "Matched operands have different values; pass value to disambiguate");
        EquateTable table = program.getEquateTable();
        Equate existing = table.getEquate(name);
        require(existing == null || existing.getValue() == selectedValue,
            "Equate '" + name + "' already exists with a different value");
        require(existing == null || !existing.isEnumBased(), "Equate is owned by an enum; use a different name");
        // Snapshot displaced references before changing anything. Keep other scalars on a compound operand.
        List<SelectedReference> displaced = new ArrayList<>();
        for (Hit hit : hits) {
            for (Equate eq : table.getEquates(hit.address(), hit.operand())) {
                if (!eq.getName().equals(name) && matches(hit.scalar(), eq.getValue())) {
                    for (EquateReference ref : references(eq)) {
                        if (ref.getAddress().equals(hit.address()) && ref.getOpIndex() == hit.operand()) {
                            displaced.add(new SelectedReference(eq, ref));
                        }
                    }
                }
            }
        }
        Equate equate = existing == null ? table.createEquate(name, selectedValue) : existing;
        for (SelectedReference ref : displaced) detach(ref);
        for (Hit hit : hits) equate.addReference(hit.address(), hit.operand());
        List<Map<String,Object>> targets = new ArrayList<>();
        for (Hit hit : hits) targets.add(JsonHelper.mapOf("address", hit.address().toString(),
            "operand_index", hit.operand(), "value", hit.value()));
        return Response.ok(JsonHelper.mapOf("action", "apply", "equate", name, "value", selectedValue,
            "created", existing == null, "applied", hits.size(), "targets", targets,
            "scope", function == null ? "instruction " + address : "function " + function.getName(),
            "program", program.getName()));
    }

    private Response remove(Program program, String name, Long value, Address address, int operandIndex,
                            Function function, boolean deleteDefinition, int maxHits) {
        require(present(name) || value != null, "name or value is required");
        require(!deleteDefinition || present(name), "delete_definition requires name");
        EquateTable table = program.getEquateTable();
        Equate named = present(name) ? table.getEquate(name) : null;
        require(!present(name) || named != null, "No equate named '" + name + "'");
        require(named == null || value == null || named.getValue() == value, "Named equate does not match value");
        require(!deleteDefinition || !named.isEnumBased(),
            "Equate is owned by an enum; detach references without delete_definition");
        Set<Address> scope = null;
        if (address != null || function != null) {
            scope = new HashSet<>();
            for (Instruction ins : instructions(program, address, function, operandIndex)) scope.add(ins.getAddress());
        }
        List<SelectedReference> selected = new ArrayList<>();
        for (Equate eq : definitions(table)) {
            if (present(name) && !eq.getName().equals(name)) continue;
            if (value != null && eq.getValue() != value) continue;
            for (EquateReference ref : references(eq)) {
                if (scope != null && !scope.contains(ref.getAddress())) continue;
                if (operandIndex >= 0 && ref.getOpIndex() != operandIndex) continue;
                selected.add(new SelectedReference(eq, ref));
            }
        }
        require(selected.size() <= maxHits,
            "Refusing to remove " + selected.size() + " references (max_hits=" + maxHits + ")");
        require(!deleteDefinition || named.getReferenceCount() == selected.size(),
            "delete_definition would remove references outside the selection");
        List<Map<String,Object>> removed = new ArrayList<>();
        for (SelectedReference ref : selected) {
            Map<String,Object> entry = new LinkedHashMap<>(referenceMap(ref.reference()));
            entry.put("name", ref.equate().getName());
            entry.put("value", ref.equate().getValue());
            removed.add(entry);
        }
        for (SelectedReference ref : selected) detach(ref);
        if (deleteDefinition) table.removeEquate(name);
        return Response.ok(JsonHelper.mapOf("action", "remove", "removed_count", selected.size(),
            "removed", removed, "definition_deleted", deleteDefinition, "program", program.getName()));
    }

    private Response rename(Program program, String name, String newName, int maxHits) throws Exception {
        require(present(name), "name is required");
        require(present(newName), "new_name is required");
        EquateTable table = program.getEquateTable();
        Equate eq = table.getEquate(name);
        require(eq != null, "No equate named '" + name + "'");
        require(!eq.isEnumBased(), "Equate is owned by an enum; rename the enum member instead");
        require(name.equals(newName) || table.getEquate(newName) == null,
            "Equate '" + newName + "' already exists");
        int count = eq.getReferenceCount();
        require(count <= maxHits, "Refusing to rename " + count + " references (max_hits=" + maxHits + ")");
        if (!name.equals(newName)) eq.renameEquate(newName);
        return Response.ok(JsonHelper.mapOf("action", "rename", "old_name", name, "new_name", newName,
            "references_preserved", count, "program", program.getName()));
    }

    private static List<Instruction> instructions(Program program, Address address, Function function, int operand) {
        List<Instruction> out = new ArrayList<>();
        if (function != null) {
            require(function.getProgram() == program, "Function belongs to another program");
            // Re-resolve under the lock: the typed selector may have been deleted since binding.
            Function current = program.getFunctionManager().getFunctionAt(function.getEntryPoint());
            require(current != null && current.getID() == function.getID(), "Selected function no longer exists");
            InstructionIterator it = program.getListing().getInstructions(current.getBody(), true);
            while (it.hasNext()) out.add(it.next());
            if (operand >= 0) require(out.stream().anyMatch(i -> operand < i.getNumOperands()),
                "operand_index is outside every instruction's operand range");
        } else {
            Instruction ins = program.getListing().getInstructionAt(address);
            require(ins != null, "No instruction at " + address);
            require(operand < ins.getNumOperands(), "operand_index is outside the instruction's operand range");
            out.add(ins);
        }
        out.sort(Comparator.comparing(Instruction::getAddress));
        return out;
    }

    private record Hit(Address address, int operand, long value, Scalar scalar) {}
    private record SelectedReference(Equate equate, EquateReference reference) {}

    private static void detach(SelectedReference selected) {
        EquateReference ref = selected.reference();
        if (ref.getDynamicHashValue() != 0) selected.equate().removeReference(ref.getDynamicHashValue(), ref.getAddress());
        else selected.equate().removeReference(ref.getAddress(), ref.getOpIndex());
    }

    private static boolean matches(Scalar scalar, long value) {
        return scalar.getUnsignedValue() == value || scalar.getSignedValue() == value;
    }

    private static List<Equate> definitions(EquateTable table) {
        List<Equate> out = new ArrayList<>();
        table.getEquates().forEachRemaining(out::add);
        out.sort(Comparator.comparing(Equate::getName));
        return out;
    }

    private static List<EquateReference> references(Equate eq) {
        List<EquateReference> out = new ArrayList<>(Arrays.asList(eq.getReferences()));
        out.sort(Comparator.comparing(EquateReference::getAddress)
            .thenComparingInt(EquateReference::getOpIndex).thenComparingLong(EquateReference::getDynamicHashValue));
        return out;
    }

    private static Map<String,Object> referenceMap(EquateReference ref) {
        return JsonHelper.mapOf("address", ref.getAddress().toString(), "operand_index", (int) ref.getOpIndex());
    }

    private static boolean present(String text) { return text != null && !text.isBlank(); }
    private static void require(boolean condition, String message) { if (!condition) throw new Refusal(message); }

    /** Strict 64-bit decimal/hex or one-character/escape syntax; never truncate malformed literals. */
    private static Long parseValue(String text) {
        if (!present(text)) return null;
        String t = text.strip();
        try {
            if (t.startsWith("'") && t.endsWith("'") && t.length() >= 3) {
                String body = t.substring(1, t.length()-1);
                if (body.length() == 1) return (long) body.charAt(0);
                if (body.matches("\\\\[xX][0-9a-fA-F]{1,4}")) return Long.parseLong(body.substring(2),16);
                if (body.length() == 2 && body.charAt(0) == '\\') {
                    return switch (body.charAt(1)) {
                        case '0' -> 0L; case 'n' -> 10L; case 't' -> 9L; case 'r' -> 13L;
                        case 'a' -> 7L; case 'b' -> 8L; case 'f' -> 12L; case 'v' -> 11L;
                        case '\\' -> 92L; case '\'' -> 39L;
                        default -> throw new NumberFormatException();
                    };
                }
                throw new NumberFormatException();
            }
            if (t.matches("[+-]?0[xX][0-9a-fA-F]+")) {
                boolean negative = t.startsWith("-");
                String digits = t.replaceFirst("^[+-]?0[xX]", "");
                BigInteger n = new BigInteger(digits,16);
                if (negative) return n.negate().longValueExact();
                if (n.bitLength() > 64) throw new NumberFormatException();
                return n.longValue();
            }
            return Long.parseLong(t);
        } catch (ArithmeticException | NumberFormatException e) {
            throw new Refusal("Invalid value: " + text);
        }
    }
}
