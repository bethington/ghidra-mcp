package com.xebyte.core.tree;

/**
 * Where a function sits in the tree: compartment slug plus how it was placed.
 * Shared by block headers, reconcile placement, and decompile calls — one type so
 * the three cannot drift on field meaning.
 */
public record CompartmentRef(
        String slug, String method, double confidence, boolean evidenceBacked) {
}
