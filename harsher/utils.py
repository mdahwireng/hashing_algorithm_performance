from sqlalchemy import create_engine


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
        exit(1)

def db_query_generator(conn, query):
    """
    A generator function that yields rows from a database query.
    
    Args:
        conn: A database connection object.
        query: The SQLAlchemy Select query.
    
    Yields:
        A Row object representing a single row from the result set.
    """
    try:
        result = conn.execute(query)
        for row in result:
            yield row
    except Exception as e:
        print(f"Database error: {e}")
        conn.rollback()
        raise
