-- Test tables for supabase-client integration tests.

CREATE TABLE IF NOT EXISTS countries (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cities (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    country_id INTEGER NOT NULL REFERENCES countries(id),
    population BIGINT DEFAULT 0,
    is_capital BOOLEAN DEFAULT FALSE,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- RPC test functions
CREATE OR REPLACE FUNCTION get_cities_by_country(p_country_id INTEGER)
RETURNS SETOF cities
LANGUAGE sql STABLE
AS $$
    SELECT * FROM cities WHERE country_id = p_country_id;
$$;

CREATE OR REPLACE FUNCTION add_numbers(a INTEGER, b INTEGER)
RETURNS INTEGER
LANGUAGE sql IMMUTABLE
AS $$
    SELECT a + b;
$$;
