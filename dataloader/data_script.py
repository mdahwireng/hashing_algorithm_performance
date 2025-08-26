import string
import logging
import math
import pandas as pd
from utils import run_zxcvbn, find_non_ascii_char, simulate_passwords, read_file, pickle_dataframe
from TreatZxcvbn import TreatZxcvbn

# Configure basic logging to the console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Log messages
logging.debug("This is a debug message.")
logging.info("This is an info message.")
logging.warning("This is a warning message.")
logging.error("This is an error message.")

# Simulation parameters
num_passwords = 1000000
min_length = 8
max_length = 20

# Simulate passwords
pswds_sim = simulate_passwords(num_passwords, min_length, max_length)

source_sim = ["simulated" for i in pswds_sim]

sp_chars = ['ñ', 'ๅ', 'ภ', 'ถ', 'ุ', 'ç', 'Ñ', 'ึ', 'ค', 'ต', 'ó', '●', 'é', 'ส', 'น', 'อ', 'ำ', 'ั', 'ี', 'ย', 'ฟ', 'ห', 'ไ', 'พ', 'ก', 'ü', 'จ', 'ß', 'ş', 'ı', 'ะ', '้', 'ร', 'ื', 'ด', '่', 'า', 'ว', 'แ', 'á', 'เ', 'ง', 'ö', '´']

# read gmail leaked passwords
logging.info("Reading leaked passwords from file...")
pswds_leaked =read_file("./data/alleged-gmail-passwords.txt")
pswds_leaked, rmv_leaked = find_non_ascii_char(pswds_leaked,sp_chars)
source_leaked = ["leaked gmail passwords" for i in pswds_leaked]


# read rockyou passwords
logging.info("Reading rockyou passwords from file...")
pswds_rock = read_file("./data/rockyou.txt")
pswds_rock, rmv_rock = find_non_ascii_char(pswds_rock,sp_chars)
source_rock = ["leaked gmail passwords" for i in pswds_rock]


# combine all passwords
logging.info("Combining all passwords...")
passwords = [*pswds_leaked, *pswds_rock, *pswds_sim]

source = [*source_leaked, *source_rock, *source_sim]


# Analyze password lengths
logging.info("Analyzing password lengths...")
password_lengths = [len(password) for password in passwords]

logging.info(f"Total passwords: {len(passwords)}")
logging.info("Creating dictionary for DataFrame...")
# Create a dictionary for DataFrame
df_dict = {"passwords":passwords, "source":source, "password_len":password_lengths}


logging.info("Creating DataFrame...")
# Create DataFrame
password_df = pd.DataFrame(df_dict)

# Run zxcvbn on passwords
logging.info("Running zxcvbn on passwords...")
password_df['zxcvbn_score'] = password_df['passwords'].apply(run_zxcvbn)

logging.info("Extracting zxcvbn results...")
treat_z = TreatZxcvbn(df=password_df)
treat_z.extract()
zxcvbn_output = treat_z.out_put()

# Create DataFrame from zxcvbn output
logging.info("Creating DataFrame from zxcvbn output...")
zxcvbn_output_keys = list(zxcvbn_output.keys())

# dataframe for zxcvbn output for password
zxcvbn_password_df = pd.DataFrame(zxcvbn_output[zxcvbn_output_keys[0]])

# dataframe for zxcvbn output for squences
sequences_password_df = pd.DataFrame(zxcvbn_output[zxcvbn_output_keys[1]])


logging.info(f"Zxcvbn password DataFrame shape: {zxcvbn_password_df.shape}")
logging.info(f"Zxcvbn sequences DataFrame shape: {sequences_password_df.shape}")


# calculate the entropy of the passwords
logging.info("Calculating entropy of passwords...")
zxcvbn_password_df['entropy'] = zxcvbn_password_df['guesses'].apply(lambda x : math.log2(x) if x else None)


# merge with password_df
logging.info("Merging zxcvbn password DataFrame with password_df...")
password_table_cols = ['passwords',
                         'source',
                         'password_len',
                         'guesses',
                         'guesses_log10',
                         'calc_time',
                         'offline_slow_hashing_1e4_per_second',
                         'offline_fast_hashing_1e10_per_second',
                         'score',
                         'entropy']

password_df = password_df.merge(zxcvbn_password_df, left_on=['passwords'], right_on=['password'])[password_table_cols]

# calculate the bytes of the passwords
logging.info("Calculating bytes of passwords...")
password_df['size_byte'] = password_df['passwords'].apply(lambda x : len(x.encode('UTF-8')) if x else None)


# calculate calc_time in microsecs
logging.info("Calculating calc_time in microseconds...")
password_df['calc_time_micros'] = password_df['calc_time'].apply(lambda x : x*1e6 if x else None)
password_df.drop(columns=['calc_time'], inplace=True)

# serialize outputs password_df, sesquences_password_df, spsp_chars, rmv_leaked, rmv_rock
logging.info("Serializing outputs...")

root_path = './data/'
outputs_df = [password_df, sequences_password_df, sp_chars, rmv_leaked, rmv_rock]
outputs_str = ['password_df', 'sequences_password_df', 'sp_chars', 'rmv_leaked', 'rmv_rock']
output_paths = [root_path+o+'.pkl' for o in outputs_str]

for d,p in zip(outputs_df,output_paths):
    pickle_dataframe(dataframe=d, filepath=p, mode='save')