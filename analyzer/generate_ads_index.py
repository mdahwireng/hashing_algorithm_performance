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
        # Fallback for local testing outside of Docker
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

# --- 2. Database Extraction ---
def fetch_and_aggregate_data():
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    query = """
        SELECT 
            a.name AS algorithm,
            ac.parameters_json AS configuration,
            hg.duration_ms AS generation_time_ms,
            hcr.duration_seconds AS cracking_time_s,
            hcr.hashes_per_second AS hashes_per_second,
            hcr.ram_usage_mb_max AS max_ram_mb
        FROM hash_cracking_results hcr
        JOIN hash_generations hg ON hcr.hash_generation_id = hg.id
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        WHERE hcr.cracked_status = 'CRACKED'
    """
    df_raw = pd.read_sql_query(query, conn)
    conn.close()
    
    # ADD THIS LINE: Convert the parsed dictionary back to a string so Pandas can group it
    df_raw['configuration'] = df_raw['configuration'].astype(str)
    
    # Group by algorithm and config to get mean performance across the cracked hashes
    return df_raw.groupby(['algorithm', 'configuration']).mean(numeric_only=True).reset_index()


def fetch_password_data():
    """Pulls the raw passwords to analyze length and complexity distributions."""
    conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
    query = "SELECT password FROM passwords;"
    df_pass = pd.read_sql_query(query, conn)
    conn.close()
    
    # Feature Engineering for Password Attributes
    df_pass['length'] = df_pass['password'].apply(len)
    df_pass['has_upper'] = df_pass['password'].apply(lambda x: any(c.isupper() for c in x))
    df_pass['has_digit'] = df_pass['password'].apply(lambda x: any(c.isdigit() for c in x))
    df_pass['has_special'] = df_pass['password'].apply(lambda x: any(c in string.punctuation for c in x))
    
    return df_pass

# --- 3. Index Calculation ---
def calculate_ads(df, weights, profile_name):
    """Standardizes metrics and calculates the final ADS score."""
    metrics = ['generation_time_ms', 'cracking_time_s', 'max_ram_mb', 'hashes_per_second']
    
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
        df_norm['max_ram_mb'] * weights[2] +
        df_norm['hashes_per_second'] * weights[3]
    )
    
    result_df = df[['algorithm', 'configuration', 'ADS_Score']].copy()
    result_df['Profile'] = profile_name
    return result_df.sort_values(by='ADS_Score', ascending=False).round(2)

# --- 4. Visualization Suite ---
def generate_visualizations(df_telemetry, df_pass, df_secure, df_auth, out_dir="/app/reports"):
    """Generates and saves the suite of 4 thesis plots."""
    print("\nGenerating visualization suite...")
    os.makedirs(out_dir, exist_ok=True)
    
    # Clean up the configuration strings for the charts (truncates long JSON)
    df_telemetry['config_short'] = df_telemetry['configuration'].astype(str).str[:30] + "..."
    df_secure['config_short'] = df_secure['configuration'].astype(str).str[:30] + "..."
    df_auth['config_short'] = df_auth['configuration'].astype(str).str[:30] + "..."

    # Plot 1: Password Distribution
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    sns.histplot(data=df_pass, x='length', bins=range(min(df_pass['length']), max(df_pass['length']) + 2), 
                 kde=True, ax=axes[0], color='skyblue')
    axes[0].set_title('Password Length Distribution')
    axes[0].set_xlabel('Character Length')
    axes[0].set_ylabel('Frequency')
    
    complexity_counts = [df_pass['has_upper'].sum(), df_pass['has_digit'].sum(), df_pass['has_special'].sum()]
    sns.barplot(x=['Uppercase', 'Digits', 'Symbols'], y=complexity_counts, ax=axes[1], hue=['Uppercase', 'Digits', 'Symbols'], palette='viridis', legend=False)
    axes[1].set_title('Password Complexity Attributes')
    axes[1].set_ylabel('Number of Passwords')
    plt.tight_layout()
    plt.savefig(f"{out_dir}/1_password_distribution.png", dpi=300)
    plt.close()

    # Plot 2: Asymmetric Trade-off
    
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=df_telemetry, 
        x='generation_time_ms', 
        y='cracking_time_s', 
        hue='algorithm', 
        size='max_ram_mb', 
        sizes=(50, 500), 
        alpha=0.8, 
        palette='Set1'
    )
    plt.xscale('log')
    plt.yscale('log')
    plt.title('Asymmetric Trade-off: Generation Cost vs. Cracking Time')
    plt.xlabel('Defender Cost: Generation Time (ms) [Log Scale]')
    plt.ylabel('Attacker Cost: Cracking Time (s) [Log Scale]')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(f"{out_dir}/2_asymmetric_tradeoff.png", dpi=300)
    plt.close()

    # Plot 3: Hardware Strain
    plt.figure(figsize=(12, 6))
    df_telemetry['algo_config'] = df_telemetry['algorithm'] + "\n" + df_telemetry['config_short']
    df_sorted_ram = df_telemetry.sort_values('max_ram_mb', ascending=False)
    sns.barplot(data=df_sorted_ram, x='algo_config', y='max_ram_mb', hue='algorithm', dodge=False, palette='mako')
    plt.xticks(rotation=45, ha='right')
    plt.title('Attacker Hardware Strain: Peak Memory Consumption')
    plt.xlabel('Algorithm & Configuration')
    plt.ylabel('Max RAM (MB)')
    plt.legend(title='Algorithm')
    plt.tight_layout()
    plt.savefig(f"{out_dir}/3_hardware_strain.png", dpi=300)
    plt.close()

    # Plot 4: Final Rankings
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    sns.barplot(data=df_secure.head(5), y='config_short', x='ADS_Score', hue='algorithm', dodge=False, ax=axes[0], palette='magma')
    axes[0].set_title('Top 5: Secure Storage Profile')
    axes[0].set_xlabel('Asymmetric Defense Score (ADS)')
    axes[0].set_ylabel('')
    
    sns.barplot(data=df_auth.head(5), y='config_short', x='ADS_Score', hue='algorithm', dodge=False, ax=axes[1], palette='crest')
    axes[1].set_title('Top 5: Web API Profile')
    axes[1].set_xlabel('Asymmetric Defense Score (ADS)')
    axes[1].set_ylabel('')
    
    plt.tight_layout()
    plt.savefig(f"{out_dir}/4_ads_rankings.png", dpi=300)
    plt.close()

# --- 5. Main Execution & Export ---
if __name__ == "__main__":
    out_dir = "/app/reports"
    print("Extracting and aggregating database telemetry...")
    
    df_aggregated = fetch_and_aggregate_data()
    
    if df_aggregated.empty:
        print("No cracked results found. Run your Hashcat nodes first!")
    else:
        # AHP Calculation
        weights_secure = calculate_ahp_weights(matrix_secure_storage, "Secure Storage")
        weights_auth = calculate_ahp_weights(matrix_user_auth, "User-Friendly Authentication")
        
        # ADS Generation
        df_secure = calculate_ads(df_aggregated.copy(), weights_secure, "Secure Storage")
        df_auth = calculate_ads(df_aggregated.copy(), weights_auth, "User-Friendly Authentication")
        
        # Console Output
        print("\nTOP RANKINGS: SECURE STORAGE PROFILE")
        print(df_secure[['algorithm', 'configuration', 'ADS_Score']].head(10).to_string(index=False))
        
        print("\nTOP RANKINGS: USER-FRIENDLY AUTHENTICATION PROFILE")
        print(df_auth[['algorithm', 'configuration', 'ADS_Score']].head(10).to_string(index=False))
        
        # File Exports
        os.makedirs(out_dir, exist_ok=True)
        df_secure.to_csv(f"{out_dir}/secure_storage_rankings.csv", index=False)
        df_auth.to_csv(f"{out_dir}/user_auth_rankings.csv", index=False)
        
        # Generate and save the plots
        df_passwords = fetch_password_data()
        generate_visualizations(df_aggregated, df_passwords, df_secure, df_auth, out_dir)
        
        print(f"\nSuccess: CSV reports and PNG visualizations successfully exported to {out_dir}/")