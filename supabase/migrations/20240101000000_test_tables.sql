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

-- Realtime test table
CREATE TABLE IF NOT EXISTS realtime_test (
    id SERIAL PRIMARY KEY,
    name VARCHAR NOT NULL,
    value VARCHAR
);

-- Enable realtime for the test table (idempotent)
DO $$
BEGIN
    ALTER PUBLICATION supabase_realtime ADD TABLE realtime_test;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;
$$;

-- Atomic test data reset function (used by REST integration tests)
CREATE OR REPLACE FUNCTION reset_test_data()
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    nz_id INTEGER;
    au_id INTEGER;
    jp_id INTEGER;
BEGIN
    DELETE FROM cities WHERE true;
    DELETE FROM countries WHERE true;

    INSERT INTO countries (name, code) VALUES ('New Zealand', 'NZ') RETURNING id INTO nz_id;
    INSERT INTO countries (name, code) VALUES ('Australia', 'AU') RETURNING id INTO au_id;
    INSERT INTO countries (name, code) VALUES ('Japan', 'JP') RETURNING id INTO jp_id;

    INSERT INTO cities (name, country_id, population, is_capital) VALUES
        ('Auckland', nz_id, 1657000, false),
        ('Wellington', nz_id, 215000, true),
        ('Sydney', au_id, 5312000, false),
        ('Canberra', au_id, 453000, true),
        ('Tokyo', jp_id, 13960000, true);
END;
$$;
