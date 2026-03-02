-- Knowledge DB Schema Extensions for RE Loop
-- Adds: ordinal_mappings, documented_functions, propagation_log
-- Target: 10.0.10.30:5432/bsim (existing BSim + pgvector database)
-- Prerequisites: 08-pgvector-and-hierarchy.sql already applied
--
-- Run with: psql -h 10.0.10.30 -U ben -d bsim -f scripts/knowledge_schema.sql

SET search_path TO public;

-- =========================================================================
-- TABLE: ordinal_mappings
-- Stores ordinal-to-name mappings per binary version.
-- Source of truth for known ordinal names across game versions.
-- =========================================================================

CREATE TABLE IF NOT EXISTS ordinal_mappings (
    id SERIAL PRIMARY KEY,
    ordinal INTEGER NOT NULL,
    binary_name VARCHAR(100) NOT NULL,      -- e.g., "D2Common.dll"
    version VARCHAR(20) NOT NULL,           -- e.g., "1.00", "1.13d"
    function_name VARCHAR(200) NOT NULL,    -- e.g., "GetUnitPosition"
    calling_convention VARCHAR(20),         -- e.g., "__stdcall", "__thiscall"
    parameter_count INTEGER,
    source VARCHAR(50) DEFAULT 're_loop',   -- "re_loop", "community", "ida_export"
    confidence FLOAT DEFAULT 1.0,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ordinal, binary_name, version)
);

CREATE INDEX IF NOT EXISTS idx_ordinal_mappings_lookup
    ON ordinal_mappings(binary_name, version, ordinal);
CREATE INDEX IF NOT EXISTS idx_ordinal_mappings_name
    ON ordinal_mappings(function_name);

-- =========================================================================
-- TABLE: documented_functions
-- Write-through cache of RE loop completed[] entries.
-- Source of truth remains loop_state.json; this enables DB queries/export.
-- =========================================================================

CREATE TABLE IF NOT EXISTS documented_functions (
    id SERIAL PRIMARY KEY,
    address VARCHAR(20) NOT NULL,           -- e.g., "0x6fd81234"
    binary_name VARCHAR(100) NOT NULL,      -- e.g., "D2Common.dll"
    version VARCHAR(20) NOT NULL,           -- e.g., "1.00", "1.13d"
    old_name VARCHAR(200),                  -- e.g., "FUN_6fd81234"
    new_name VARCHAR(200) NOT NULL,         -- e.g., "GetUnitPosition"
    score INTEGER,                          -- completeness score 0-100
    status VARCHAR(20) DEFAULT 'complete',  -- complete, documented, needs_work, failed
    classification VARCHAR(20),             -- thunk, leaf, worker, api
    iteration INTEGER,
    strategy VARCHAR(30),                   -- callee_first, high_xref, etc.
    plate_comment TEXT,                     -- function summary/documentation
    prototype TEXT,                         -- function signature
    deductions JSONB DEFAULT '[]',          -- list of score deductions
    game_system VARCHAR(100),              -- e.g., "inventory", "combat"
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(address, binary_name, version)
);

CREATE INDEX IF NOT EXISTS idx_documented_functions_binary
    ON documented_functions(binary_name, version);
CREATE INDEX IF NOT EXISTS idx_documented_functions_system
    ON documented_functions(game_system) WHERE game_system IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_documented_functions_name
    ON documented_functions(new_name);
CREATE INDEX IF NOT EXISTS idx_documented_functions_score
    ON documented_functions(score DESC);

-- Full-text search index for keyword queries
ALTER TABLE documented_functions ADD COLUMN IF NOT EXISTS search_vector tsvector;

CREATE OR REPLACE FUNCTION documented_functions_search_update()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.new_name, '') || ' ' ||
        COALESCE(NEW.plate_comment, '') || ' ' ||
        COALESCE(NEW.game_system, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_documented_functions_search ON documented_functions;
CREATE TRIGGER trigger_documented_functions_search
    BEFORE INSERT OR UPDATE ON documented_functions
    FOR EACH ROW
    EXECUTE FUNCTION documented_functions_search_update();

CREATE INDEX IF NOT EXISTS idx_documented_functions_search
    ON documented_functions USING gin(search_vector);

-- =========================================================================
-- TABLE: propagation_log
-- Records cross-version function match propagations.
-- =========================================================================

CREATE TABLE IF NOT EXISTS propagation_log (
    id SERIAL PRIMARY KEY,
    source_address VARCHAR(20) NOT NULL,
    source_binary VARCHAR(100) NOT NULL,
    source_version VARCHAR(20) NOT NULL,
    target_address VARCHAR(20) NOT NULL,
    target_binary VARCHAR(100) NOT NULL,
    target_version VARCHAR(20) NOT NULL,
    match_type VARCHAR(20) NOT NULL,        -- "hash", "bsim", "fuzzy"
    confidence FLOAT NOT NULL,
    function_name VARCHAR(200),
    applied BOOLEAN DEFAULT FALSE,
    iteration INTEGER,
    details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_propagation_log_source
    ON propagation_log(source_binary, source_version, source_address);
CREATE INDEX IF NOT EXISTS idx_propagation_log_target
    ON propagation_log(target_binary, target_version, target_address);
CREATE INDEX IF NOT EXISTS idx_propagation_log_type
    ON propagation_log(match_type, confidence DESC);

-- =========================================================================
-- updated_at triggers (reuse existing function if available)
-- =========================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_ordinal_mappings_updated_at ON ordinal_mappings;
CREATE TRIGGER trigger_ordinal_mappings_updated_at
    BEFORE UPDATE ON ordinal_mappings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_documented_functions_updated_at ON documented_functions;
CREATE TRIGGER trigger_documented_functions_updated_at
    BEFORE UPDATE ON documented_functions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =========================================================================
-- KNOWLEDGE SOURCE: Insert re_loop as a knowledge source
-- (for community_insights foreign key, if used later)
-- =========================================================================

INSERT INTO knowledge_sources (name, source_type, trust_score, quality_score, metadata)
VALUES ('RE Loop (ghidra-mcp)', 'manual_entry', 1.0, 0.9, '{"tool": "ghidra-mcp", "version": "4.2.0"}')
ON CONFLICT (url) DO NOTHING;

-- =========================================================================
-- VERIFICATION
-- =========================================================================

SELECT tablename FROM pg_tables
WHERE schemaname = 'public'
AND tablename IN ('ordinal_mappings', 'documented_functions', 'propagation_log')
ORDER BY tablename;
