import os
import textwrap
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text


def build_database_uri() -> str:
    db_user = os.getenv("DB_USER", "postgres")
    db_host = os.getenv("DB_HOST", "db")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "hash_store")

    # Read password like dataloader via Docker secret
    secret_path = os.getenv("DB_PASSWORD_FILE", "/run/secrets/db_password")
    try:
        with open(secret_path, "r", encoding="utf-8") as f:
            db_password = f.read().strip()
    except OSError:
        db_password = os.getenv("DB_PASSWORD", "")

    return f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = build_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bootstrap = Bootstrap5(app)


def ensure_schema_constraints():
    # Ensure comparison_algo_configs exists and has necessary columns and constraints
    with db.engine.begin() as conn:
        # Ensure table exists
        conn.execute(text(textwrap.dedent(
            """
            CREATE TABLE IF NOT EXISTS comparison_algo_configs (
                comp_id BIGINT NOT NULL,
                algo_config_id BIGINT NOT NULL,
                PRIMARY KEY (comp_id, algo_config_id)
            );
            """
        )))
        # Ensure comp_id column exists (older deployments might be missing it)
        conn.execute(text(textwrap.dedent(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='comparison_algo_configs' AND column_name='comp_id'
                ) THEN
                    ALTER TABLE comparison_algo_configs
                    ADD COLUMN comp_id BIGINT;
                END IF;
            END
            $$;
            """
        )))
        # Add FKs if missing
        conn.execute(text(textwrap.dedent(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'comparison_algo_configs_comp_id_fkey'
                ) THEN
                    ALTER TABLE comparison_algo_configs
                    ADD CONSTRAINT comparison_algo_configs_comp_id_fkey
                    FOREIGN KEY (comp_id) REFERENCES comparisons(id) ON DELETE CASCADE;
                END IF;

                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'comparison_algo_configs_algo_config_id_fkey'
                ) THEN
                    ALTER TABLE comparison_algo_configs
                    ADD CONSTRAINT comparison_algo_configs_algo_config_id_fkey
                    FOREIGN KEY (algo_config_id) REFERENCES algorithm_configurations(id) ON DELETE CASCADE;
                END IF;
            END
            $$;
            """
        )))


_schema_checked = False


@app.before_request
def _check_schema_once():
    global _schema_checked
    if not _schema_checked:
        try:
            ensure_schema_constraints()
        except OSError:
            pass
        _schema_checked = True


@app.route("/")
def index():
    return redirect(url_for("about"))


@app.route("/about")
def about():
    readme_html = None
    # Prefer project-level README mounted to /app/README.md
    if os.path.exists("README.md"):
        try:
            with open("README.md", "r", encoding="utf-8") as f:
                readme_html = f.read()
        except OSError:
            readme_html = ""
    return render_template("about.html", readme_markdown=readme_html)


@app.route("/comparisons", methods=["GET", "POST"])
def comparisons():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("Name is required", "danger")
            return redirect(url_for("comparisons"))

        with db.engine.begin() as conn:
            # Create or get comparison
            result = conn.execute(text(
                "INSERT INTO comparisons(name, description) VALUES (:n, :d) ON CONFLICT(name) DO UPDATE SET description = EXCLUDED.description RETURNING id"
            ), {"n": name, "d": description})
            comp_id = result.scalar()

            # Fetch all algorithms
            algos = conn.execute(text("SELECT id, name, parameters FROM algorithms ORDER BY name")).mappings().all()

            for algo in algos:
                algorithm_id = algo["id"]
                param_defs = algo["parameters"] if algo["parameters"] is not None else {}

                # Build parameters_json from submitted fields
                submitted_params = {}
                for param_key in param_defs.keys():
                    field_name = f"algo_{algorithm_id}_{param_key}"
                    value = request.form.get(field_name, "").strip()
                    if value != "":
                        submitted_params[param_key] = value

                # If nothing submitted, fall back to empty object
                parameters_json = submitted_params

                # Insert/find configuration with submitted parameters
                ac_result = conn.execute(text(
                    """
                    INSERT INTO algorithm_configurations(algorithm_id, parameters_json)
                    VALUES (:algorithm_id, CAST(:parameters_json AS JSONB))
                    ON CONFLICT DO NOTHING
                    RETURNING id
                    """
                ), {"algorithm_id": algorithm_id, "parameters_json": json.dumps(parameters_json)})
                alg_config_id = ac_result.scalar()

                if alg_config_id is None:
                    existing = conn.execute(text(
                        """
                        SELECT id FROM algorithm_configurations
                        WHERE algorithm_id = :algorithm_id AND parameters_json = CAST(:parameters_json AS JSONB)
                        LIMIT 1
                        """
                    ), {"algorithm_id": algorithm_id, "parameters_json": json.dumps(parameters_json)}).scalar()
                    alg_config_id = existing

                # Map comparison to algorithm configuration
                conn.execute(text(
                    """
                    INSERT INTO comparison_algo_configs(comp_id, algo_config_id)
                    VALUES (:comp_id, :alg_config_id)
                    ON CONFLICT DO NOTHING
                    """
                ), {"comp_id": comp_id, "alg_config_id": alg_config_id})

                # Register an experiment run for this configuration
                conn.execute(text(
                    """
                    INSERT INTO experiment_runs(alg_config_id, status, description)
                    VALUES (:alg_config_id, 'registered', :desc)
                    """
                ), {"alg_config_id": alg_config_id, "desc": f"Registered for comparison {name}"})

        flash("Comparison saved with algorithm parameters.", "success")
        return redirect(url_for("comparisons"))

    # GET: list comparisons and linked algorithm configurations, plus algorithm param defs for form
    with db.engine.begin() as conn:
        comps = conn.execute(text("SELECT id, name, description FROM comparisons ORDER BY id DESC")).mappings().all()
        comp_details = []
        for c in comps:
            algo_rows = conn.execute(text(textwrap.dedent(
                """
                SELECT ac.id, a.name, ac.parameters_json
                FROM comparison_algo_configs cac
                JOIN algorithm_configurations ac ON ac.id = cac.algo_config_id
                JOIN algorithms a ON a.id = ac.algorithm_id
                WHERE cac.comp_id = :comp_id
                ORDER BY a.name
                """
            )), {"comp_id": c["id"]}).mappings().all()
            comp_details.append({
                "id": c["id"],
                "name": c["name"],
                "description": c["description"],
                "algorithms": algo_rows,
            })

        # Algorithms for entry form
        algorithms = conn.execute(text("SELECT id, name, parameters FROM algorithms ORDER BY id")).mappings().all()

    return render_template("comparisons.html", comparisons=comp_details, algorithms=algorithms)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)


