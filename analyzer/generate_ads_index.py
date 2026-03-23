import os
import string
import pandas as pd
import numpy as np
import psycopg2
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import matplotlib.pyplot as plt
import seaborn as sns

# Set the academic plotting style for thesis-ready graphics
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)

def get_db_password(secret_path='/run/secrets/db_password'):
    """Reads the database password from Docker secrets."""
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception:
        return "postgres"

# Use Docker networking environment variables
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "hash_store")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = get_db_password()

# --- 1. AHP Weight Calculation ---
def calculate_ahp_weights(matrix, profile_name):
    """Calculates AHP weights and verifies the Consistency Ratio (CR)."""
    n = matrix.shape[0]
    column_sums = matrix.sum(axis=0)
    normalized_matrix = matrix / column_sums
    weights = normalized_matrix.mean(axis=1)
    
    weighted_sum_vector = np.dot(matrix, weights)
    lambda_max = (weighted_sum_vector / weights).mean()
    
    ci = (lambda_max - n) / (n - 1)
    ri_dict = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}
    ri = ri_dict[n]
    cr = ci / ri if ri > 0 else 0
    
    print(f"\n--- AHP Verification: {profile_name} ---")
    print(f"Weights (T_gen, T_crack, M_crack, H_rate): {np.round(weights, 3)}")
    print(f"Consistency Ratio (CR): {cr:.3f} -> {'VALID' if cr < 0.1 else 'INVALID (Adjust Matrix!)'}")
    
    return weights

# Matrices [T_gen, T_crack, M_crack, H_rate]
matrix_secure_storage = np.array([
    [1,   1/7, 1/7, 1/5],
    [7,   1,   1,   3  ],
    [7,   1,   1,   3  ],
    [5,   1/3, 1/3, 1  ]
])

matrix_user_auth = np.array([
    [1,   3,   5,   7  ],
    [1/3, 1,   3,   5  ],
    [1/5, 1/3, 1,   2  ],
    [1/7, 1/5, 1/2, 1  ]
])

# --- 2. Database Extraction Functions ---
def get_db_connection():
    return psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)

def fetch_aggregated_data():
    """Fetches core benchmarking telemetry for ADS calculation."""
    query = """
        SELECT 
            a.name AS algorithm,
            ac.parameters_json AS configuration,
            hg.duration_ms AS generation_time_ms,
            hcr.duration_seconds AS cracking_time_s,
            hcr.hashes_per_second AS hashes_per_second,
            COALESCE(hcr.ram_usage_mb_max, 0) AS max_ram_mb,
            COALESCE(hcr.gpu_memory_mb_max, 0) AS max_gpu_vram_mb
        FROM hash_cracking_results hcr
        JOIN hash_generations hg ON hcr.hash_generation_id = hg.id
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        WHERE hcr.cracked_status = 'CRACKED'
    """
    with get_db_connection() as conn:
        df_raw = pd.read_sql_query(query, conn)
    
    if df_raw.empty: return df_raw
    
    df_raw['configuration'] = df_raw['configuration'].astype(str)
    df_raw['total_memory_cost_mb'] = df_raw['max_ram_mb'] + df_raw['max_gpu_vram_mb']
    return df_raw.groupby(['algorithm', 'configuration']).mean(numeric_only=True).reset_index()

def fetch_password_data():
    """Pulls raw passwords and schema-defined entropy metrics."""
    query = "SELECT password, password_len, entropy FROM passwords;"
    with get_db_connection() as conn:
        df_pass = pd.read_sql_query(query, conn)
    # Feature Engineering for complexity types
    df_pass['has_upper'] = df_pass['password'].apply(lambda x: any(c.isupper() for c in str(x)))
    df_pass['has_digit'] = df_pass['password'].apply(lambda x: any(c.isdigit() for c in str(x)))
    df_pass['has_special'] = df_pass['password'].apply(lambda x: any(c in string.punctuation for c in str(x)))
    return df_pass

def fetch_comparison_data():
    """Pulls environment-specific baseline vs OWASP comparisons."""
    query = """
        SELECT 
            c.name AS comparison_name,
            a.name AS algorithm,
            ac.parameters_json AS configuration,
            AVG(hg.duration_ms) AS generation_time_ms,
            AVG(hcr.duration_seconds) AS cracking_time_s
        FROM comparisons c
        JOIN comparison_algo_configs cac ON c.id = cac.comp_id
        JOIN algorithm_configurations ac ON cac.algo_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        JOIN experiment_runs er ON ac.id = er.alg_config_id
        JOIN hash_generations hg ON er.id = hg.experiment_run_id
        JOIN hash_cracking_results hcr ON hg.id = hcr.hash_generation_id
        WHERE hcr.cracked_status = 'CRACKED'
        GROUP BY c.name, a.name, ac.parameters_json
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)

def fetch_entropy_performance_data():
    """Pulls unaggregated hash cracking data mapped to password entropy."""
    query = """
        SELECT 
            p.password_len, 
            p.entropy, 
            a.name AS algorithm,
            hg.duration_ms AS generation_time_ms,
            hcr.duration_seconds AS cracking_time_s
        FROM passwords p
        JOIN hash_generations hg ON p.id = hg.password_id
        JOIN hash_cracking_results hcr ON hg.id = hcr.hash_generation_id
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        WHERE hcr.cracked_status = 'CRACKED'
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)

def fetch_hardware_stability_data():
    """Pulls defender generation memory telemetry for stability analysis."""
    query = """
        SELECT 
            a.name AS algorithm,
            ac.parameters_json AS configuration,
            hg.memory_peak_mb_during_hash
        FROM hash_generations hg
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)

def fetch_attack_type_data():
    """Pulls cracking efficacy by attack type (e.g. Mode 0 vs Mode 3)."""
    query = """
        SELECT 
            cat.name AS attack_mode,
            a.name AS algorithm,
            AVG(hcr.duration_seconds) AS cracking_time_s
        FROM cracking_attack_types cat
        JOIN hash_cracking_results hcr ON cat.id = hcr.cracking_attack_type_id
        JOIN hash_generations hg ON hcr.hash_generation_id = hg.id
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        WHERE hcr.cracked_status = 'CRACKED'
        GROUP BY cat.name, a.name
    """
    with get_db_connection() as conn:
        return pd.read_sql_query(query, conn)

# --- 3. Mathematical Calculations ---
def calculate_ads(df, weights, profile_name):
    """Standardizes metrics and calculates the final ADS score."""
    metrics = ['generation_time_ms', 'cracking_time_s', 'total_memory_cost_mb', 'hashes_per_second']
    scaler = StandardScaler()
    df_z = pd.DataFrame(scaler.fit_transform(df[metrics]), columns=metrics)
    
    # Invert 'lower is better' metrics
    df_z['generation_time_ms'] = df_z['generation_time_ms'] * -1
    df_z['hashes_per_second'] = df_z['hashes_per_second'] * -1
    
    minmax = MinMaxScaler(feature_range=(0, 100))
    df_norm = pd.DataFrame(minmax.fit_transform(df_z), columns=metrics)
    
    df['ADS_Score'] = (
        df_norm['generation_time_ms'] * weights[0] +
        df_norm['cracking_time_s'] * weights[1] +
        df_norm['total_memory_cost_mb'] * weights[2] +
        df_norm['hashes_per_second'] * weights[3]
    )
    
    result_df = df[['algorithm', 'configuration', 'ADS_Score']].copy()
    result_df['Profile'] = profile_name
    # Clean up config strings for plotting
    result_df['config_short'] = result_df['configuration'].astype(str).str[:30] + "..."
    return result_df.sort_values(by='ADS_Score', ascending=False).round(2)

def calculate_pareto_frontier(df):
    """Identifies optimal configs (minimize Gen Time, maximize Crack Time)."""
    # Sort by Defender Cost (Ascending) and Attacker Cost (Descending)
    df_sorted = df.sort_values(['generation_time_ms', 'cracking_time_s'], ascending=[True, False])
    pareto_front = []
    max_crack_time_seen = -1
    
    for _, row in df_sorted.iterrows():
        if row['cracking_time_s'] > max_crack_time_seen:
            pareto_front.append(row)
            max_crack_time_seen = row['cracking_time_s']
            
    return pd.DataFrame(pareto_front)

# --- 4. Visualization Suite ---
def generate_visualizations(out_dir="/app/reports"):
    print("\nGenerating comprehensive visualization suite...")
    os.makedirs(out_dir, exist_ok=True)
    
    # 1. Base Aggregated Telemetry
    df_agg = fetch_aggregated_data()
    if not df_agg.empty:
        df_agg['config_short'] = df_agg['configuration'].astype(str).str[:30] + "..."
        
        # Plot 1: Asymmetric Trade-off
        plt.figure(figsize=(10, 6))
        sns.scatterplot(data=df_agg, x='generation_time_ms', y='cracking_time_s', 
                        hue='algorithm', size='total_memory_cost_mb', sizes=(50, 500), alpha=0.8)
        plt.xscale('log'); plt.yscale('log')
        plt.title('Asymmetric Trade-off: Generation vs. Cracking Cost')
        plt.xlabel('Defender Cost: Generation Time (ms) [Log]'); plt.ylabel('Attacker Cost: Cracking Time (s) [Log]')
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout(); plt.savefig(f"{out_dir}/1_asymmetric_tradeoff.png", dpi=300); plt.close()

        # Plot 2: Pareto Frontier
        df_pareto = calculate_pareto_frontier(df_agg)
        plt.figure(figsize=(10, 6))
        sns.scatterplot(data=df_agg, x='generation_time_ms', y='cracking_time_s', color='lightgrey', label='Suboptimal')
        sns.lineplot(data=df_pareto, x='generation_time_ms', y='cracking_time_s', color='red', marker='o', label='Pareto Frontier')
        plt.xscale('log'); plt.yscale('log')
        plt.title('Pareto Frontier Optimization (Algorithm Configurations)')
        plt.xlabel('Generation Time (ms) [Minimize]'); plt.ylabel('Cracking Time (s) [Maximize]')
        plt.legend()
        plt.tight_layout(); plt.savefig(f"{out_dir}/2_pareto_frontier.png", dpi=300); plt.close()

        # Plot 3: Hardware Strain
        plt.figure(figsize=(12, 6))
        df_agg['algo_config'] = df_agg['algorithm'] + "\n" + df_agg['config_short']
        df_sorted_ram = df_agg.sort_values('total_memory_cost_mb', ascending=False)
        sns.barplot(data=df_sorted_ram, x='algo_config', y='total_memory_cost_mb', hue='algorithm', dodge=False)
        plt.xticks(rotation=45, ha='right')
        plt.title('Attacker Hardware Strain (System + VRAM)')
        plt.ylabel('Total Memory (MB)')
        plt.tight_layout(); plt.savefig(f"{out_dir}/3_hardware_strain.png", dpi=300); plt.close()
        
        # ADS Scores (Plots 4 & 5)
        w_secure = calculate_ahp_weights(matrix_secure_storage, "Secure Storage")
        w_auth = calculate_ahp_weights(matrix_user_auth, "Web API")
        df_secure = calculate_ads(df_agg.copy(), w_secure, "Secure Storage")
        df_auth = calculate_ads(df_agg.copy(), w_auth, "Web API")
        
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        sns.barplot(data=df_secure.head(5), y='config_short', x='ADS_Score', hue='algorithm', dodge=False, ax=axes[0], palette='magma')
        axes[0].set_title('Top 5: Secure Storage Profile')
        sns.barplot(data=df_auth.head(5), y='config_short', x='ADS_Score', hue='algorithm', dodge=False, ax=axes[1], palette='crest')
        axes[1].set_title('Top 5: Web API Profile')
        plt.tight_layout(); plt.savefig(f"{out_dir}/4_ads_rankings.png", dpi=300); plt.close()

        # Plot 5: Profile ADS Shifts
        df_combined_ads = pd.concat([df_secure, df_auth])
        plt.figure(figsize=(10, 8))
        sns.pointplot(data=df_combined_ads, x='Profile', y='ADS_Score', hue='config_short', markers="o", linestyles="-")
        plt.title('ADS Score Shift by Environmental Profile')
        plt.ylabel('Asymmetric Defense Score (0-100)'); plt.xlabel('')
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout(); plt.savefig(f"{out_dir}/5_profile_ads_shifts.png", dpi=300); plt.close()

    # 6. Password Complexity & Distribution
    df_pass = fetch_password_data()
    if not df_pass.empty:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        sns.histplot(data=df_pass, x='password_len', kde=True, ax=axes[0], color='skyblue')
        axes[0].set_title('Password Length Distribution')
        axes[0].set_xlabel('Character Length')
        
        comp_counts = [df_pass['has_upper'].sum(), df_pass['has_digit'].sum(), df_pass['has_special'].sum()]
        sns.barplot(x=['Uppercase', 'Digits', 'Symbols'], y=comp_counts, ax=axes[1], palette='viridis')
        axes[1].set_title('Password Complexity Attributes')
        plt.tight_layout(); plt.savefig(f"{out_dir}/6_password_distribution.png", dpi=300); plt.close()

    # 7 & 8. Entropy and Length impacts
    df_ent = fetch_entropy_performance_data()
    if not df_ent.empty:
        plt.figure(figsize=(10, 6))
        sns.lmplot(data=df_ent, x='entropy', y='cracking_time_s', hue='algorithm', scatter_kws={'alpha':0.5}, aspect=1.5)
        plt.yscale('log')
        plt.title('Impact of Password Entropy on Cracking Time')
        plt.xlabel('Password Entropy (Bits)'); plt.ylabel('Cracking Time (s) [Log]')
        plt.tight_layout(); plt.savefig(f"{out_dir}/7_entropy_vs_cracking.png", dpi=300); plt.close('all')

        plt.figure(figsize=(12, 6))
        sns.boxenplot(data=df_ent, x='password_len', y='generation_time_ms', hue='algorithm')
        plt.title('Impact of Password Length on Generation Cost')
        plt.xlabel('Password Length (Characters)'); plt.ylabel('Generation Time (ms)')
        plt.tight_layout(); plt.savefig(f"{out_dir}/8_length_vs_generation.png", dpi=300); plt.close()

    # 9. Comparison Groups (Baseline vs OWASP)
    df_comp = fetch_comparison_data()
    if not df_comp.empty:
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        sns.barplot(data=df_comp, x='algorithm', y='generation_time_ms', hue='comparison_name', ax=axes[0], palette='viridis')
        axes[0].set_title('Defender Cost: Gen Time by Environment')
        sns.barplot(data=df_comp, x='algorithm', y='cracking_time_s', hue='comparison_name', ax=axes[1], palette='magma')
        axes[1].set_yscale('log')
        axes[1].set_title('Attacker Cost: Crack Time by Environment (Log)')
        plt.tight_layout(); plt.savefig(f"{out_dir}/9_environment_comparisons.png", dpi=300); plt.close()

    # 10. Hardware Stability (Defender)
    df_stab = fetch_hardware_stability_data()
    if not df_stab.empty:
        plt.figure(figsize=(12, 6))
        sns.boxplot(data=df_stab, x='algorithm', y='memory_peak_mb_during_hash', palette='coolwarm')
        plt.title('Defender Hardware Stability: Memory Variance During Hashing')
        plt.ylabel('Peak RAM Usage (MB)')
        plt.tight_layout(); plt.savefig(f"{out_dir}/10_defender_hardware_stability.png", dpi=300); plt.close()

    # 11. Attack Mode Efficacy
    df_attack = fetch_attack_type_data()
    if not df_attack.empty:
        plt.figure(figsize=(10, 6))
        sns.barplot(data=df_attack, x='algorithm', y='cracking_time_s', hue='attack_mode', palette='Set2')
        plt.yscale('log')
        plt.title('Attack Mode Efficacy: Cracking Time Variance')
        plt.ylabel('Cracking Time (s) [Log]')
        plt.tight_layout(); plt.savefig(f"{out_dir}/11_attack_mode_efficacy.png", dpi=300); plt.close()

# --- 5. Main Execution ---
if __name__ == "__main__":
    out_dir = "/app/reports"
    print("Extracting and aggregating multidimensional telemetry...")
    try:
        generate_visualizations(out_dir)
        print(f"\nSuccess: 11-Plot Thesis Visualization Suite successfully exported to {out_dir}/")
    except Exception as e:
        print(f"Error during analysis: {e}")