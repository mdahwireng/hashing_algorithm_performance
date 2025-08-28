import json
import os
import dotenv
from sqlalchemy import text

from utils import get_db_password, query_table_count, create_db_connection


algorithms = [
    {
        "algorithm": "bcrypt",
        "parameters": {
            "password_plaintext": "The password string to be hashed.",
            "rounds": "The computational cost of the hashing algorithm, default is 12."
    }
    },

    {
        "algorithm": "argon2",
        "parameters": {
            "password_plaintext": "The password string to be hashed.",
            "t": "The time cost of the hashing algorithm, default is 2.",
            "m": "The memory cost of the hashing algorithm in kibibytes, default is 102400 (100 MB).",
            "p": "The number of parallel threads, default is 8.",
            "salt_bytes": "The length of the random salt in bytes, default is 16."
        }
    },

    {
        "algorithm": "scrypt",
        "parameters": {
            "password_plaintext": "The password string to be hashed.",
            "N": "The CPU/memory cost parameter, default is 16384.",
            "r": "The block size parameter, default is 8.",
            "p": "The parallelization parameter, default is 1.",
            "dklen": "The length of the derived key, default is 64.",
            "salt_bytes": "The length of the random salt in bytes, default is 16."
        }
    },

    {
        "algorithm": "pbkdf2_sha256",
        "parameters": {
            "password_plaintext": "The password string to be hashed.",
            "salt_bytes": "The length of the random salt in bytes, default is 16.",
            "dklen": "The length of the derived key, default is 32.",
            "hash_algo": "The underlying hash algorithm, such as `sha256` or `sha512`, default is sha256",
            "iterations": "The number of times the function is run. Higher values increase security but require more processing time, default is 100000."
        }
    }
]



dotenv.load_dotenv(dotenv_path='./data/.env')

db_user = os.getenv('DB_USER')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')

db_password = get_db_password()

print("Alogrithm loading task initiated...")

# create a database connection
print("Establishing database connection...")
conn = create_db_connection(db_user, db_password, db_host, db_port, db_name)

#retrive info from algorithm table

sql_str = text("SELECT name FROM algorithms")
result = conn.execute(sql_str)
algo_names = result.fetchall()


insert_sql = text("INSERT INTO algorithms (name, parameters) VALUES (:name , :parameter)")

for alg in algorithms:
    if alg not in algo_names:
        print("Unloaded entry found loading to db ...")
        n = alg['algorithm']
        param = json.dumps(alg['parameters'])

        conn.execute(insert_sql, {"name":n, "parameter":param})

conn.commit()
conn.close()

print("Database connection closed..")

print("Alogrithm loading task completed...")




