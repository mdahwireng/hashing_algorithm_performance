import json
import os
import dotenv
from sqlalchemy import text

from utils import get_db_password, create_db_connection

attack_types = [
    {
        "name": "Database Dictionary Attack",
        "description": "Pure dictionary attack. The cracker will stream plaintext passwords from the DB to use as the wordlist.",
        "parameters_json": {
            "mode": "0"
        }
    },
    {
        "name": "Rule-Based DB Dictionary",
        "description": "Dictionary attack using a ruleset. The cracker will apply rules to the dynamically generated DB wordlist.",
        "parameters_json": {
            "mode": "0",
            "rule": "best64.rule"
        }
    },
    {
        "name": "Mask Brute-Force (8 char)",
        "description": "Exhaustive brute force using a defined 8-character mixed mask. No wordlist required.",
        "parameters_json": {
            "mode": "3",
            "mask": "?a?a?a?a?a?a?a?a"
        }
    },
    {
        "name": "Combinator Attack",
        "description": "Combining two wordlists. The cracker will handle list generation/mounting.",
        "parameters_json": {
            "mode": "1"
        }
    }
]

dotenv.load_dotenv(dotenv_path='./data/.env')

db_user = os.getenv('DB_USER')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')

db_password = get_db_password()

print("Attack type loading task initiated...")

# create a database connection
print("Establishing database connection...")
conn = create_db_connection(db_user, db_password, db_host, db_port, db_name)

# retrieve info from cracking_attack_types table
sql_str = text("SELECT name FROM cracking_attack_types")
result = conn.execute(sql_str)
existing_types = result.fetchall()
existing_types = [item[0] for item in existing_types if existing_types]

insert_sql = text("""
    INSERT INTO cracking_attack_types (name, description, parameters_json) 
    VALUES (:name, :description, :parameters_json)
""")

for attack in attack_types:
    if attack["name"] not in existing_types:
        print(f"Unloaded entry '{attack['name']}' found, loading to db ...")
        
        n = attack['name']
        desc = attack['description']
        param = json.dumps(attack['parameters_json'])

        conn.execute(insert_sql, {"name": n, "description": desc, "parameters_json": param})

conn.commit()
conn.close()

print("Database connection closed..")
print("Attack type loading task completed...")