import os
import subprocess
import psycopg2
import time
import psutil
import threading

# Safely import NVIDIA ML library for GPU telemetry
try:
    import pynvml
    HAS_PYNVML = True
except ImportError:
    HAS_PYNVML = False


def get_db_password(secret_path='/run/secrets/db_password'):
    """Reads the database password from a secure Docker secret file."""
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"Error reading database password from '{secret_path}': {e}")
        exit(1)


# --- Configuration & Environment Variables ---
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "hash_store")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASS = get_db_password()
ATTACK_TYPE_ID = int(os.environ.get("ATTACK_TYPE_ID", 1))
CRACK_SAMPLE_LIMIT = int(os.environ.get("CRACK_SAMPLE_LIMIT", 100))

# --- File Paths for Hashcat v7+ ---
WORDLIST_PATH = "/tmp/db_wordlist.txt"
HASH_FILE_PATH = "/tmp/target_hash.txt"
POTFILE_PATH = "/tmp/hashcat.potfile"
HASHCAT_BIN = "/opt/hashcat/hashcat"   # Forcing the custom-built v7 binary
RULES_DIR = "/opt/hashcat/rules"       # Using the v7 rules folder


class HardwareMonitor:
    """Runs in a background thread to poll CPU, System RAM, and GPU metrics while Hashcat executes."""
    def __init__(self):
        self.running = False
        self.cpu_usages = []
        self.ram_usages = []
        self.gpu_usages = []
        self.gpu_mems = []
        self.has_gpu = False
        
        if HAS_PYNVML:
            try:
                pynvml.nvmlInit()
                self.has_gpu = pynvml.nvmlDeviceGetCount() > 0
            except:
                self.has_gpu = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor)
        self.thread.start()

    def _monitor(self):
        # Poll hardware every 0.5 seconds
        while self.running:
            self.cpu_usages.append(psutil.cpu_percent(interval=None))
            
            # Poll System RAM usage in Megabytes
            ram_info = psutil.virtual_memory()
            self.ram_usages.append(ram_info.used / (1024 * 1024))
            
            if self.has_gpu:
                try:
                    handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                    util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    self.gpu_usages.append(util.gpu)
                    self.gpu_mems.append(mem.used / (1024 * 1024)) # Convert bytes to MB
                except:
                    pass
            time.sleep(0.5)

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join()

    def get_metrics(self):
        return {
            "cpu_avg": sum(self.cpu_usages) / len(self.cpu_usages) if self.cpu_usages else 0.0,
            "cpu_max": max(self.cpu_usages) if self.cpu_usages else 0.0,
            "ram_avg": sum(self.ram_usages) / len(self.ram_usages) if self.ram_usages else 0.0,
            "ram_max": max(self.ram_usages) if self.ram_usages else 0.0,
            "gpu_avg": sum(self.gpu_usages) / len(self.gpu_usages) if self.gpu_usages else 0.0,
            "gpu_max": max(self.gpu_usages) if self.gpu_usages else 0.0,
            "gpu_mem_avg": sum(self.gpu_mems) / len(self.gpu_mems) if self.gpu_mems else 0.0,
            "gpu_mem_max": max(self.gpu_mems) if self.gpu_mems else 0.0
        }


def get_db_connection():
    return psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)


def build_dynamic_wordlist(experiment_run_id):
    """Streams a dynamically filtered wordlist containing ONLY the passwords used in this specific experiment run."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT DISTINCT p.password 
        FROM passwords p
        JOIN hash_generations hg ON hg.password_id = p.id
        WHERE hg.experiment_run_id = %s
    """, (experiment_run_id,))
    
    passwords = cursor.fetchall()
    count = len(passwords)
    
    with open(WORDLIST_PATH, "w", encoding="utf-8") as f:
        for row in passwords:
            f.write(f"{row[0]}\n")
            
    cursor.close()
    conn.close()
    
    return count


def get_hashcat_module(algo_name):
    """Maps the algorithm name to its Hashcat v7+ module code."""
    algo_lower = algo_name.lower().strip()
    
    # In Hashcat v7+, Argon2 is strictly module 34000
    if algo_lower == "argon2" or algo_lower.startswith("argon2"):
        return "34000"  
            
    mapping = {
        "bcrypt": "3200",
        "scrypt": "8900",
        "pbkdf2_sha256": "10900"
    }
    
    return mapping.get(algo_lower)


def build_hashcat_command(module_code, attack_params):
    """Constructs the Hashcat subprocess command dynamically based on DB JSON parameters."""
    mode = attack_params.get("mode", "0")
    
    # Base command explicitly calling the /opt/hashcat/hashcat binary
    command = [HASHCAT_BIN, "-m", module_code, "-a", mode, HASH_FILE_PATH, "--self-test-disable"]
    
    if mode == "0":
        # Straight Dictionary Attack
        command.append(WORDLIST_PATH)
        
        # Check if a rule mutation is requested
        if "rule" in attack_params:
            rule_path = os.path.join(RULES_DIR, attack_params["rule"])
            command.extend(["-r", rule_path])
            
    elif mode == "3":
        # Mask Attack / Brute-Force
        if "mask" in attack_params:
            command.append(attack_params["mask"])
            
    elif mode == "1":
        # Combinator Attack
        command.extend([WORDLIST_PATH, WORDLIST_PATH])

    # Append standard operational flags
    command.extend([
        "--potfile-path", POTFILE_PATH,
        "--status", "--status-timer=1", "--machine-readable"
    ])
    
    return command


def run_crack_job():
    """Fetches a pending hash, generates a targeted wordlist, executes Hashcat, and records telemetry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Fetch the Attack Parameters
    cursor.execute("SELECT parameters_json FROM cracking_attack_types WHERE id = %s", (ATTACK_TYPE_ID,))
    attack_row = cursor.fetchone()
    if not attack_row:
        print(f"Critical Error: ATTACK_TYPE_ID {ATTACK_TYPE_ID} not found in database.")
        cursor.close()
        conn.close()
        return False
        
    attack_params = attack_row[0]
    
    # 2. Retrieve one uncracked hash, enforcing sample limits and isolating by ATTACK_TYPE_ID
    cursor.execute("""
        SELECT 
            hg.id, 
            hg.generated_hash, 
            a.name AS algorithm_name,
            er.id AS experiment_run_id
        FROM hash_generations hg
        JOIN experiment_runs er ON hg.experiment_run_id = er.id
        JOIN algorithm_configurations ac ON er.alg_config_id = ac.id
        JOIN algorithms a ON ac.algorithm_id = a.id
        LEFT JOIN hash_cracking_results hcr ON hg.id = hcr.hash_generation_id 
                                            AND hcr.cracking_attack_type_id = %(attack_type)s
        WHERE hcr.id IS NULL
          AND (
              SELECT COUNT(hcr_count.id) 
              FROM hash_cracking_results hcr_count 
              JOIN hash_generations hg_count ON hcr_count.hash_generation_id = hg_count.id
              WHERE hg_count.experiment_run_id = er.id 
                AND hcr_count.cracking_attack_type_id = %(attack_type)s
          ) < %(limit)s
        ORDER BY hg.id ASC
        LIMIT 1
    """, {"attack_type": ATTACK_TYPE_ID, "limit": CRACK_SAMPLE_LIMIT})
    
    job = cursor.fetchone()
    
    if not job:
        cursor.close()
        conn.close()
        return False
        
    hg_id, target_hash, algo_name, experiment_run_id = job
    module_code = get_hashcat_module(algo_name)
    
    if not module_code:
        print(f"Error: Algorithm '{algo_name}' not mapped to a Hashcat module. Skipping.")
        cursor.execute("""
            INSERT INTO hash_cracking_results (
                hash_generation_id, cracking_attack_type_id, duration_seconds, 
                hashes_per_second, cracked_status
            ) VALUES (%s, %s, 0, 0, 'UNSUPPORTED_ALGO')
        """, (hg_id, ATTACK_TYPE_ID))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    
    # 3. Prepare the environment
    clean_hash = target_hash.strip().strip('"').strip("'")
    with open(HASH_FILE_PATH, "w", encoding="utf-8") as f:
        f.write(clean_hash + "\n")
        
    if os.path.exists(POTFILE_PATH):
        os.remove(POTFILE_PATH)

    # 4. Build the targeted wordlist
    print(f"Generating dynamic wordlist for Run ID: {experiment_run_id}...")
    wordlist_size = build_dynamic_wordlist(experiment_run_id)
    print(f"Targeted wordlist created with {wordlist_size} guaranteed passwords.")
    
    if wordlist_size == 0:
        print(f"Skipping ID {hg_id}: No passwords found for Run ID '{experiment_run_id}'.")
        cursor.execute("""
            INSERT INTO hash_cracking_results (
                hash_generation_id, cracking_attack_type_id, duration_seconds, 
                hashes_per_second, cracked_status
            ) VALUES (%s, %s, 0, 0, 'SKIPPED_EMPTY_WORDLIST')
        """, (hg_id, ATTACK_TYPE_ID))
        conn.commit()
        cursor.close()
        conn.close()
        return True

    # 5. Construct the dynamic command
    command = build_hashcat_command(module_code, attack_params)

    print(f"Starting ID {hg_id} | DB Algo: {algo_name} | Module: {module_code} | Mode: {attack_params.get('mode')} | Attack ID: {ATTACK_TYPE_ID}")
    
    # 6. Start Telemetry and Execution
    monitor = HardwareMonitor()
    monitor.start()
    start_time = time.time()
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    speed_hps = 0.0
    error_log = []
    
    # Parse the machine-readable stdout
    for line in process.stdout:
        if line.startswith("STATUS"):
            parts = line.split('\t')
            if len(parts) > 5:
                try:
                    speed_hps = float(parts[4]) 
                except ValueError:
                    pass
        else:
            if line.strip():
                error_log.append(line.strip())
                    
    process.wait()
    duration = time.time() - start_time
    
    # If it failed to launch, dump the error log
    if speed_hps == 0.0:
        print(f"\n--- HASHCAT FATAL ERROR FOR ID {hg_id} ---")
        for err in error_log:
            print(err)
        print("-------------------------------------------\n")

    # Stop Telemetry
    monitor.stop()
    metrics = monitor.get_metrics()
    
    # 7. Check Results
    cracked_password = None
    cracked_status = "FAILED"
    
    if os.path.exists(POTFILE_PATH):
        with open(POTFILE_PATH, "r") as f:
            pot_data = f.read().strip()
            if pot_data:
                cracked_password = pot_data.split(":")[-1]
                cracked_status = "CRACKED"

    print(f"Result: {cracked_status} in {duration:.2f}s | Speed: {speed_hps} H/s")

    # 8. Save Telemetry to Database
    cursor.execute("""
        INSERT INTO hash_cracking_results (
            hash_generation_id, cracking_attack_type_id, duration_seconds, 
            hashes_per_second, cracked_status, cracked_password,
            cpu_usage_percent_avg, cpu_usage_percent_max,
            ram_usage_mb_avg, ram_usage_mb_max,
            gpu_usage_percent_avg, gpu_usage_percent_max,
            gpu_memory_mb_avg, gpu_memory_mb_max
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        hg_id, ATTACK_TYPE_ID, duration, speed_hps, cracked_status, cracked_password,
        metrics['cpu_avg'], metrics['cpu_max'], 
        metrics['ram_avg'], metrics['ram_max'],
        metrics['gpu_avg'], metrics['gpu_max'],
        metrics['gpu_mem_avg'], metrics['gpu_mem_max']
    ))
    
    conn.commit()
    cursor.close()
    conn.close()
    return True


if __name__ == "__main__":
    print(f"Initializing Cracker Service for Attack Type {ATTACK_TYPE_ID}...")
    
    # Wait briefly for the DB to be fully ready
    time.sleep(5) 

    # Main Daemon Loop
    while True:
        try:
            has_jobs = run_crack_job()
            if not has_jobs:
                # Sleep if there are no hashes left to crack for this specific attack type
                time.sleep(10)
        except Exception as e:
            print(f"Error during cracking loop: {e}")
            time.sleep(10)