import os
import random
import string
import pickle
from zxcvbn import zxcvbn
from sqlalchemy import create_engine
import pandas as pd

def run_zxcvbn(psswd):
    if not psswd:
        return None
    if len(psswd) > 72:
        return zxcvbn(psswd[:72])
    return zxcvbn(psswd)


def find_non_ascii_char(passwords,non_ascii_chars):
    sp_pswd_lst = []
    for p in passwords:
        for sp in non_ascii_chars:
            if sp in p:
                sp_pswd_lst.append(p)
    
    sp_pswd_set = list(set(sp_pswd_lst))
    clean_pswd = [pswd for pswd in passwords if pswd not in sp_pswd_set]

    return clean_pswd, sp_pswd_set


def generate_random_password(length):
    """Generates a random password of specified length."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


def simulate_passwords(num_passwords, min_length, max_length):
    """Simulates a given number of passwords with varying lengths."""
    passwords = []
    for _ in range(num_passwords):
        length = random.randint(min_length, max_length)
        password = generate_random_password(length)
        passwords.append(password)
    return passwords


def read_file(file_path):
    with open(file_path, 'r') as f:
        count = 1
        words = []
        try:
            for l in f:
                if len(l) > 150:
                    continue
                count += 1
                words.append(l.strip())
        except UnicodeDecodeError as e:
            pass
            
    return words



def pickle_dataframe(dataframe=None, filepath: str = 'data.pkl', mode: str = 'save'):
    """
    Saves a Pandas DataFrame to a pickle file or loads a DataFrame from a pickle file.

    Args:
        dataframe (pd.DataFrame, optional): The DataFrame to be saved.
                                            Required if mode is 'save'. Defaults to None.
        filepath (str): The path to the pickle file. Defaults to 'data.pkl'.
        mode (str): The operation mode. Must be 'save' or 'load'. Defaults to 'save'.

    Returns:
        pd.DataFrame or None: If mode is 'load', turns the loaded DataFrame.
                              If mode is 'save' or an error occurs, turns None.

    Raises:
        ValueError: If an invalid mode is provided or if 'save' mode is
                    called without a DataFrame.
    """
    if mode not in ['save', 'load']:
        raise ValueError("Invalid mode. Must be 'save' or 'load'.")

    if mode == 'save':
        if dataframe is None:
            raise ValueError("DataFrame must be provided when mode is 'save'.")
        try:
            with open(filepath, 'wb') as file:
                pickle.dump(dataframe, file)
            print(f"DataFrame successfully saved to '{filepath}'")
            return None
        except Exception as e:
            print(f"Error saving DataFrame to '{filepath}': {e}")
            return None
    elif mode == 'load':
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' not found.")
            return None
        try:
            with open(filepath, 'rb') as file:
                loaded_df = pickle.load(file)
            print(f"DataFrame successfully loaded from '{filepath}'")
            return loaded_df
        except Exception as e:
            print(f"Error loading DataFrame from '{filepath}': {e}")
            return None
        
def create_db_connection(user, password, host, port, database):
    """
    Creates a SQLAlchemy database connection.

    Args:
        user (str): Database username.
        password (str): Database password.
        host (str): Database host address.
        port (int): Database port number.
        database (str): Database name.

    Returns:
        sqlalchemy.engine.base.Connection: A SQLAlchemy connection object.
    """
    try:
        engine = create_engine(f'postgresql://{user}:{password}@{host}:{port}/{database}')
        connection = engine.connect()
        print("Database connection established.")
        return connection
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return None
    
def get_db_password(secret_path='/run/secrets/db_password'):
    """
    Reads the database password from a secure file.

    Args:
        secret_path (str): Path to the file containing the database password.

    Returns:
        str: The database password.
    """
    try:
        with open(secret_path, 'r') as f:
            db_password = f.read().strip()
        return db_password
    except Exception as e:
        print(f"Error reading database password from '{secret_path}': {e}")
        return None

def query_table_count(connection, table_name):
    """
    Queries the total number of records in a specified table.

    Args:
        connection (sqlalchemy.engine.base.Connection): A SQLAlchemy connection object.
        table_name (str): The name of the table to query.

    Returns:
        int: The total number of records in the table.
    """
    try:
        sql_str = "SELECT COUNT(*) FROM :table_name"
        result = connection.execute(sql_str, {"table_name":table_name})
        count = result.scalar()
        print(f"Total records in '{table_name}': {count}")
        return count
    except Exception as e:
        print(f"Error querying table '{table_name}': {e}")
        return None
    
def get_passwords_pk(connection, table_name):
    """
    Retrieves all passwords and their primary keys from a specified table.

    Args:
        connection (sqlalchemy.engine.base.Connection): A SQLAlchemy connection object.
        table_name (str): The name of the table to query.

    Returns:
        list of tuples: A list of tuples containing primary keys and passwords.
    """
    try:
        sql_str = "SELECT :id, :columns FROM :table_name"
        result = connection.execute(sql_str, {"table_name":table_name, "id":"id", "columns":"passwords"})
        passwords = result.fetchall()
        print(f"Retrieved {len(passwords)} passwords from '{table_name}'.")
        return passwords
    except Exception as e:
        print(f"Error retrieving passwords from table '{table_name}': {e}")
        return None