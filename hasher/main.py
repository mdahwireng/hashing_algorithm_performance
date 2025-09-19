import subprocess
from sqlalchemy import text
import json
import sys
import cpuinfo
import psutil

from utils import create_db_connection, get_db_password, db_query_generator, pickle_object
import dotenv
import os
import time


dotenv.load_dotenv(dotenv_path='./data/.env')

db_user = os.getenv('DB_USER')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')
algorithm = os.getenv('ALGORITHM')
password_score_threshold = int(os.getenv('PASSWORD_SCORE_THRESHOLD', '0'))



db_password = get_db_password()

# create a database connection
print("Establishing database connection...")
conn = create_db_connection(db_user, db_password, db_host, db_port, db_name)

algo_retrive_query = text(f"""
                        SELECT er.id exp_id, ac.parameters_json
                        FROM public.experiment_runs AS er
                        INNER JOIN public.algorithm_configurations AS ac
                        ON er.alg_config_id = ac.id
                        INNER JOIN public.algorithms AS a
                        ON ac.algorithm_id = a.id
                        WHERE er.status = 'registered' AND a.name = '{algorithm}' 
                        LIMIT 1
                        """)

algo_info = conn.execute(algo_retrive_query).fetchone()
while algo_info is None:
    print(f"No registered experiment run found for algorithm '{algorithm}'. waiting.")
    time.sleep(10)
    algo_info = conn.execute(algo_retrive_query).fetchone()
    
algo_info = algo_info._asdict()
experiment_run_id = algo_info['exp_id']
parameters_json = algo_info['parameters_json']



password_retrieve_query = text(f"""
                SELECT id, password
                FROM passwords
                WHERE score > {password_score_threshold} 
                """)


insert_query = text(f"""
                            INSERT INTO public.hash_generations(
                            experiment_run_id, 
                            password_id, 
                            generated_hash, 
                            salt, 
                            start_time_utc, 
                            end_time_utc, 
                            duration_ms, 
                            cpu_user_time_ms, 
                            cpu_system_time_ms, 
                            memory_rss_mb_start, 
                            memory_peak_mb_during_hash)
                            VALUES (
                            :experiment_run_id,
                            :password_id,
                            :generated_hash,
                            :salt,
                            :start_time_utc,
                            :end_time_utc,
                            :duration_ms,
                            :cpu_user_time_ms,
                            :cpu_system_time_ms,
                            :memory_rss_mb_start,
                            :memory_peak_mb_during_hash
                                );
                            """)





if __name__ == "__main__":


    parameters_json = dict()

    parameters_json['algorithm'] = algorithm

    parameters_json['parameters'] = algo_info['parameters_json']

    exp_run_status_update_query = text("""
                UPDATE 
                    experiment_runs
                SET  
                    status = :status
                WHERE
                    id = :id
                """)
    conn.execute(exp_run_status_update_query, {'status' : 'running', 'id': experiment_run_id})
    conn.commit()

    
    run_start_time = 0
    for row in db_query_generator(conn, password_retrieve_query):
        row = row._asdict()
        password_id = row['id']
        password_plaintext = row['password']


        parameters_json['password_plaintext'] = password_plaintext

        # json.dump(parameters_json, open(f"parameters.json", "w"))

        pickle_object(parameters_json, 'parameters.pkl', mode='save')

        results_json = {"experiment_run_id": experiment_run_id, "password__id": password_id }

        # json.dump(results_json, open(f"results.json", "w"))
        pickle_object(results_json, 'results.pkl', mode='save')

        subprocess.run(["python3", "hasher.py"], stderr=sys.stderr, stdout=sys.stdout, check=True)

        # results_json = json.load(open('results.json', 'r'))
        results_json = pickle_object('-', 'results.pkl', mode='load')

        if run_start_time == 0 :
            run_start_time = results_json['start_time_utc']
        
        run_end_time = results_json['end_time_utc']

        

        insert_query_dict = {
            'experiment_run_id' : results_json['experiment_run_id'],
            'password_id' : results_json['password_id'],
            'generated_hash' : results_json['generated_hash'],
            'salt' : results_json['salt'],
            'start_time_utc' : results_json['start_time_utc'],
            'end_time_utc' : results_json['end_time_utc'],
            'duration_ms' : results_json['duration_ms'],
            'cpu_user_time_ms' : results_json['cpu_user_time_ms'],
            'cpu_system_time_ms' : results_json['cpu_system_time_ms'],
            'memory_rss_mb_start' : results_json['memory_rss_mb_start'],
            'memory_peak_mb_during_hash' : results_json['memory_peak_mb_during_hash']
        }
        
        conn.execute(insert_query, insert_query_dict)

    cpu_info = cpuinfo.get_cpu_info()
    memory = psutil.virtual_memory()

    hadware_info_dict = { 
        "cpu" : {
            "cpu_brand": cpu_info['brand_raw'],
            "cpu_vendor_id": cpu_info['vendor_id_raw'],
            "cpu_architecture": cpu_info['arch'],
            "cpu_cores": cpu_info['count'],
            "cpu_l2_cache_size": cpu_info['l2_cache_size'],
            "cpu_l3_cache_size": cpu_info['l3_cache_size'],
            "cpu_model": cpu_info['model'],
            "cpu_base_frequency": cpu_info['hz_advertised_friendly']
                },
        "memory" : {
            "total_ram_gb": f"{memory.total / (1024**3):.2f} GB",}
        }

    exp_run_update_query = text("""
                    UPDATE 
                        experiment_runs
                    SET 
                        start_time = :start_time, 
                        end_time = :end_time, 
                        status = :status, 
                        hardware_info = CAST(:hardware_info AS JSONB)
                    WHERE
                        id = :id
                    """)

    placeholder_dict = {
        'start_time' : run_start_time, 
        'end_time' : run_end_time,
        'status' : 'completed',
        'hardware_info' : json.dumps(hadware_info_dict),
        'id' : experiment_run_id
    }
    
    conn.execute(exp_run_update_query, placeholder_dict)
    conn.commit()