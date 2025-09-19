import json
import os
import dotenv
from sqlalchemy import text

from utils import get_db_password, query_table_count, create_db_connection


algorithms = [
    {
        "algorithm": "bcrypt",
        "parameters": 
            {
                "password_plaintext": 
                    {
                            "desc" : "The password string to be hashed. Leave empty to use the password from the database.",
                            "type": "string"
                    }, 
                "rounds": 
                    {
                        "desc": "The computational cost of the hashing algorithm, default is 12.",
                        "type": "integer",

                    }
            }
    },

    {
        "algorithm": "argon2",
        "parameters": 
            {
                "password_plaintext": 
                    {
                        "desc":"The password string to be hashed. Leave empty to use the password from the database.",
                        "type": "string"
                    }, 
                "t": 
                    {
                        "desc" :"The time cost of the hashing algorithm, default is 2.",
                        "type": "integer"
                    },
                "m": 
                    {
                        "desc" : "The memory cost of the hashing algorithm in kibibytes, default is 102400 (100 MB).",
                        "type": "integer"
                    },
                "p":
                    {
                        "desc" : "The number of parallel threads, default is 8.",
                        "type": "integer"
                    },
                "salt_bytes":
                    {
                        "desc" : "The length of the random salt in bytes, default is 16.",
                        "type": "integer"
                    }
            }
    },

    {
        "algorithm": "scrypt",
        "parameters": 
            {
                "password_plaintext": 
                    {
                        "desc" : "The password string to be hashed. Leave empty to use the password from the database.",
                        "type": "string"
                    }, 
                "N": 
                    {
                        "desc" : "The CPU/memory cost parameter, default is 16384.",
                        "type": "integer"
                    },
                "r": 
                    {
                        "desc" : "The block size parameter, default is 8.",
                        "type": "integer"
                    },
                "p": 
                    {
                        "desc" : "The parallelization parameter, default is 1.",
                        "type": "integer"
                    },
                "dklen": 
                    {
                        "desc" : "The length of the derived key, default is 64.",
                        "type": "integer"
                    },
                "salt_bytes": 
                    {
                        "desc" : "The length of the random salt in bytes, default is 16.",
                        "type": "integer"
                    }
            }
    },

    {
        "algorithm": "pbkdf2_sha256",
        "parameters": 
        {
            "password_plaintext": 
                {
                    "desc" : "The password string to be hashed. Leave empty to use the password from the database.",
                    "type": "string"
                },
                "salt_bytes": 
                {
                    "desc" : "The length of the random salt in bytes, default is 16.",
                    "type": "integer"
                },
                "dklen": 
                {
                    "desc" : "The length of the derived key, default is 32.",
                    "type": "integer"
                },
            "iterations": 
                {
                    "desc" : "The number of times the function is run. Higher values increase security but require more processing time, default is 100000.",
                    "type": "integer"
                }
        }
    },
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
algo_names = [item[0] for item in algo_names if algo_names]


insert_sql = text("INSERT INTO algorithms (name, parameters) VALUES (:name , :parameter)")

for alg in algorithms:
    if alg["algorithm"] not in algo_names:
        print(algo_names, alg)
        print("Unloaded entry found loading to db ...")
        n = alg['algorithm']
        param = json.dumps(alg['parameters'])

        conn.execute(insert_sql, {"name":n, "parameter":param})

conn.commit()
conn.close()

print("Database connection closed..")

print("Alogrithm loading task completed...")




