CREATE DATABASE hash_store;

\c hash_store;


-- Ensure the 'passwords' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "passwords" (
  "id" BIGSERIAL PRIMARY KEY,
  "passwords" TEXT NOT NULL,
  "source" TEXT,
  "password_len" INT NOT NULL,
  "guesses" NUMERIC,
  "guesses_log10" DOUBLE PRECISION,
  "calc_time_micros" BIGINT,
  "offline_slow_hashing_1e4_per_second" DOUBLE PRECISION,
  "offline_fast_hashing_1e10_per_second" DOUBLE PRECISION,
  "score" DOUBLE PRECISION,
  "entropy" DOUBLE PRECISION,
  "size_byte" INT
);

-- Ensure the 'sequences' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "sequences" (
  "id" BIGSERIAL PRIMARY KEY,
  "password_id" BIGINT NOT NULL,
  "pattern" TEXT NOT NULL,
  "token" TEXT NOT NULL,
  "guesses_log10" DOUBLE PRECISION NOT NULL
);

-- Ensure the 'algorithms' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "algorithms" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT UNIQUE NOT NULL,
  "parameters" JSONB
);

-- Ensure the 'experiment_runs' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "experiment_runs" (
  "id" BIGSERIAL PRIMARY KEY,
  "alg_config_id" BIGINT NOT NULL,
  "start_time" TIMESTAMPTZ NOT NULL,
  "end_time" TIMESTAMPTZ,
  "status" TEXT NOT NULL,
  "description" TEXT,
  "hardware_info" JSONB
);

-- Ensure the 'algorithm_configurations' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "algorithm_configurations" (
  "id" BIGSERIAL PRIMARY KEY,
  "algorithm_id" INT NOT NULL,
  "parameters_json" JSONB NOT NULL
);

-- Ensure the 'hash_generations' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "hash_generations" (
  "id" BIGSERIAL PRIMARY KEY,
  "experiment_run_id" BIGINT NOT NULL,
  "password_id" BIGINT NOT NULL,
  "generated_hash" TEXT NOT NULL,
  "salt" TEXT NOT NULL,
  "start_time_utc" TIMESTAMPTZ NOT NULL,
  "end_time_utc" TIMESTAMPTZ NOT NULL,
  "duration_ms" DOUBLE PRECISION NOT NULL,
  "cpu_user_time_ms" DOUBLE PRECISION NOT NULL,
  "cpu_system_time_ms" DOUBLE PRECISION NOT NULL,
  "memory_rss_mb_start" DOUBLE PRECISION NOT NULL,
  "memory_rss_mb_end" DOUBLE PRECISION NOT NULL,
  "memory_peak_mb_during_hash" DOUBLE PRECISION NOT NULL
);

-- Ensure the 'cracking_attack_types' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "cracking_attack_types" (
  "id" SERIAL PRIMARY KEY,
  "name" TEXT UNIQUE NOT NULL,
  "description" TEXT,
  "parameters_json" JSONB
);

-- Ensure the 'hash_cracking_results' table is created only if it doesn't already exist.
CREATE TABLE IF NOT EXISTS "hash_cracking_results" (
  "id" BIGSERIAL PRIMARY KEY,
  "hash_generation_id" BIGINT NOT NULL,
  "cracking_attack_type_id" INT NOT NULL,
  "duration_seconds" DOUBLE PRECISION NOT NULL,
  "hashes_per_second" DOUBLE PRECISION NOT NULL,
  "cracked_status" TEXT NOT NULL,
  "cracked_password" TEXT,
  "cpu_usage_percent_avg" DOUBLE PRECISION,
  "cpu_usage_percent_max" DOUBLE PRECISION,
  "gpu_usage_percent_avg" DOUBLE PRECISION,
  "gpu_usage_percent_max" DOUBLE PRECISION,
  "gpu_memory_mb_avg" DOUBLE PRECISION,
  "gpu_memory_mb_max" DOUBLE PRECISION
);

-- The `ALTER TABLE` statements for adding foreign keys also need to be conditional.
-- We can't use `ALTER TABLE IF NOT EXISTS` directly for foreign keys, so we
-- have to use a `DO` block with a PL/pgSQL function to check for the constraint's existence.

-- Check and add foreign key for sequences table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'sequences_password_id_fkey'
    ) THEN
        ALTER TABLE "sequences" ADD FOREIGN KEY ("password_id") REFERENCES "passwords" ("id");
    END IF;
END
$$;

-- Check and add foreign key for algorithm_configurations table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'algorithm_configurations_algorithm_id_fkey'
    ) THEN
        ALTER TABLE "algorithm_configurations" ADD FOREIGN KEY ("algorithm_id") REFERENCES "algorithms" ("id");
    END IF;
END
$$;

-- Check and add foreign key for hash_generations table (experiment_run_id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'hash_generations_experiment_run_id_fkey'
    ) THEN
        ALTER TABLE "hash_generations" ADD FOREIGN KEY ("experiment_run_id") REFERENCES "experiment_runs" ("id");
    END IF;
END
$$;

-- Check and add foreign key for hash_generations table (password_id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'hash_generations_password_id_fkey'
    ) THEN
        ALTER TABLE "hash_generations" ADD FOREIGN KEY ("password_id") REFERENCES "passwords" ("id");
    END IF;
END
$$;

-- Check and add foreign key for experiment_runs table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'experiment_runs_alg_config_id_fkey'
    ) THEN
        ALTER TABLE "experiment_runs" ADD FOREIGN KEY ("alg_config_id") REFERENCES "algorithm_configurations" ("id");
    END IF;
END
$$;

-- Check and add foreign key for hash_cracking_results table (hash_generation_id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'hash_cracking_results_hash_generation_id_fkey'
    ) THEN
        ALTER TABLE "hash_cracking_results" ADD FOREIGN KEY ("hash_generation_id") REFERENCES "hash_generations" ("id");
    END IF;
END
$$;

-- Check and add foreign key for hash_cracking_results table (cracking_attack_type_id)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM   pg_constraint
        WHERE  conname = 'hash_cracking_results_cracking_attack_type_id_fkey'
    ) THEN
        ALTER TABLE "hash_cracking_results" ADD FOREIGN KEY ("cracking_attack_type_id") REFERENCES "cracking_attack_types" ("id");
    END IF;
END
$$;
