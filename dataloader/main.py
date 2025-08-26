import os
import subprocess
import sys
from sqlalchemy import create_engine
from utils import create_db_connection, get_db_password, query_table_count, pickle_dataframe, get_passwords_pk
import dotenv
import pandas as pd



dotenv.load_dotenv(dotenv_path='./data/.env')

db_user = os.getenv('DB_USER')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')


################# Functions #################

def load_to_db(root_path, outputs_str, conn):
    print("Loading pickled data...")
    dataframes = {}
    for name in outputs_str:
        df = pickle_dataframe(f"{root_path}/{name}.pkl", mode='load')
        if df is not None:
            dataframes[name] = df
        else:
            print(f"Failed to load DataFrame '{name}' from pickle file.")
            sys.exit(1)
    print("All DataFrames loaded successfully from pickle files.")

    # load passwords_df to db
    print("Loading DataFrames into the database...")
    print("Populating the passwords table in the database...")
    dataframes['password_df'].to_sql('passwords', conn, if_exists='append', index=False)

    # get passwords ids 
    passwords_ids_df = pd.DataFrame(get_passwords_pk(conn, 'passwords'), columns=['password_id', 'passwords'])

    # merge sequences_password_df with passwords_ids_df to get password_id
    dataframes['sequences_password_df'] = dataframes['sequences_password_df'].merge(passwords_ids_df, on='passwords', how='left')
    dataframes['sequences_password_df'] = dataframes['sequences_password_df'][['password_id', 'pattern', 'token', 'guesses_log10']]

    # load sequences_password_df to db
    print("Populating the sequences table in the database...")
    dataframes['sequences_password_df'].to_sql('sequences', conn, if_exists='append', index=False)
    print("DataFrames successfully loaded into the database.")







    
################# Main Script #################

root_path = './data/'
outputs_str = ['password_df', 'sequences_password_df', 'sp_chars', 'rmv_leaked', 'rmv_rock']


# read the database password from the secrets file
with open('/run/secrets/db_password', 'r') as f:
    db_password = f.read().strip()

# create a database connection
print("Establishing database connection...")
conn = create_db_connection(db_user, db_password, db_host, db_port, db_name)


if not conn:
    print("Failed to connect to the database. Exiting...")
    sys.exit(1)

passwords_count = query_table_count(conn, 'passwords')
sequences_count = query_table_count(conn, 'sequences')

data_in_db = (passwords_count > 0) and (sequences_count > 0)

# list data directory to check for existance of pickled data
files_exist = set([t + '.pkl' for t in outputs_str]) == set([t for t in os.listdir(root_path) if t.endswith('pkl')])



if (not files_exist and not data_in_db):

    print("No pickled data found and database is empty. Running data processing script...")

    subprocess.run(['python3', 'data_script.py'], stdout=sys.stdout, stderr=sys.stderr, check=True)

    # load pickled data
    load_to_db(root_path, outputs_str, conn)
elif (files_exist and not data_in_db):

    print("Pickled data found and database is empty. Loading data into the database...")
    # load pickled data
    load_to_db(root_path, outputs_str, conn)
elif data_in_db:
    print("Data already exists in the database. No action needed.")