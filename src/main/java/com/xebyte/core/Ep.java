package com.xebyte.core;

import java.util.Map;

/**
 * Declarative endpoint table — sealed interface with one record per HTTP helper pattern.
 * Extracted from EndpointRouter so both GUI and headless can share the same table.
 */
public sealed interface Ep {
    String path();

    // Functional interfaces for endpoint handlers
    @FunctionalInterface interface PageFn   { Response apply(int offset, int limit, String prog) throws Exception; }
    @FunctionalInterface interface PageFn1  { Response apply(String p, int offset, int limit, String prog) throws Exception; }
    @FunctionalInterface interface PageFn1R { Response apply(int offset, int limit, String p, String prog) throws Exception; }
    @FunctionalInterface interface Fn0      { Response apply() throws Exception; }
    @FunctionalInterface interface Fn1      { Response apply(String p1) throws Exception; }
    @FunctionalInterface interface Fn2      { Response apply(String p1, String p2) throws Exception; }
    @FunctionalInterface interface Fn3      { Response apply(String p1, String p2, String p3) throws Exception; }
    @FunctionalInterface interface Fn4      { Response apply(String p1, String p2, String p3, String p4) throws Exception; }
    @FunctionalInterface interface PageFn0  { Response apply(int offset, int limit) throws Exception; }
    @FunctionalInterface interface PageFn1NP { Response apply(String p, int offset, int limit) throws Exception; }
    @FunctionalInterface interface JsonHandler { Response apply(Map<String, Object> params) throws Exception; }
    @FunctionalInterface interface QueryHandler { Response apply(Map<String, String> params) throws Exception; }

    // GET patterns
    record Get0(String path, Fn0 fn) implements Ep {}
    record Get1(String path, String p1, Fn1 fn) implements Ep {}
    record Get2(String path, String p1, String p2, Fn2 fn) implements Ep {}
    record Get3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
    record Get4(String path, String p1, String p2, String p3, String p4, Fn4 fn) implements Ep {}
    record GetPage(String path, PageFn fn) implements Ep {}
    record GetPage1(String path, String pName, PageFn1 fn) implements Ep {}
    record GetPage1R(String path, String pName, PageFn1R fn) implements Ep {}
    record GetPageNP(String path, PageFn0 fn) implements Ep {}
    record GetPage1NP(String path, String pName, PageFn1NP fn) implements Ep {}
    record GetQuery(String path, QueryHandler fn) implements Ep {}

    // POST patterns
    record Post1(String path, String p1, Fn1 fn) implements Ep {}
    record Post2(String path, String p1, String p2, Fn2 fn) implements Ep {}
    record Post3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
    record Json1(String path, String p1, Fn1 fn) implements Ep {}
    record Json2(String path, String p1, String p2, Fn2 fn) implements Ep {}
    record Json3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
    record Json4(String path, String p1, String p2, String p3, String p4, Fn4 fn) implements Ep {}
    record JsonPost(String path, JsonHandler fn) implements Ep {}
}
