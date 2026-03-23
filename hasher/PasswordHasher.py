import os
import hashlib
import bcrypt
import base64
import argon2
from argon2 import PasswordHasher as Argon2PasswordHasher

class PasswordHasher:
    """
    A class to encapsulate various password hashing algorithms.

    This class provides a unified interface for different hashing algorithms,
    handling the specifics of salt generation, parameter passing, and ensuring
    Hashcat-compatible Modular Crypt Format (MCF) outputs.
    """

    def __init__(self, algorithm, **kwargs):
        self.algorithm = algorithm.lower()
        self.params = kwargs

        # Dictionary to map algorithm names to their hashing methods.
        self.hasher_methods = {
            'pbkdf2_sha256': self._hash_pbkdf2,
            'pbkdf2': self._hash_pbkdf2,  # Added to support the example block
            'bcrypt': self._hash_bcrypt,
            'scrypt': self._hash_scrypt,
            'argon2': self._hash_argon2
        }

        if self.algorithm not in self.hasher_methods:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_hash(self, password_plaintext):
        hasher_func = self.hasher_methods[self.algorithm]
        return hasher_func(password_plaintext, **self.params)

    def _generate_salt(self, length):
        return os.urandom(length)

    def _hash_pbkdf2(self, password_plaintext, **kwargs):
        iterations = int(kwargs.get('iterations', 100000))
        dklen = int(kwargs.get('dklen', 32))
        hash_algo = kwargs.get('hash_algo', 'sha256')
        salt_length = int(kwargs.get('salt_bytes', 16))
        
        salt_bytes = self._generate_salt(length=salt_length)

        derived_key = hashlib.pbkdf2_hmac(
            hash_name=hash_algo,
            password=password_plaintext.encode('utf-8'),
            salt=salt_bytes,
            iterations=iterations,
            dklen=dklen
        )
        
        # Format for Hashcat Module 10900 (sha256:iterations:base64_salt:base64_hash)
        b64_salt = base64.b64encode(salt_bytes).decode('utf-8')
        b64_hash = base64.b64encode(derived_key).decode('utf-8')
        hashcat_ready_string = f"{hash_algo}:{iterations}:{b64_salt}:{b64_hash}"
        
        return b64_salt, hashcat_ready_string

    def _hash_bcrypt(self, password_plaintext, **kwargs):
        rounds = int(kwargs.get('rounds', 12))
        salt_bytes = bcrypt.gensalt(rounds=rounds)

        # Bcrypt natively returns a Hashcat-compatible MCF string
        hashed = bcrypt.hashpw(password_plaintext.encode('utf-8'), salt_bytes)
        
        return salt_bytes.decode('utf-8'), hashed.decode('utf-8')

    def _hash_scrypt(self, password_plaintext, **kwargs):
        N = int(kwargs.get('N', 16384))
        r = int(kwargs.get('r', 8))
        p = int(kwargs.get('p', 1))
        dklen = int(kwargs.get('dklen', 32))
        salt_length = int(kwargs.get('salt_bytes', 16))
        
        salt_bytes = self._generate_salt(length=salt_length)

        derived_key = hashlib.scrypt(
            password=password_plaintext.encode('utf-8'),
            salt=salt_bytes,
            n=N, r=r, p=p,
            dklen=dklen,
            maxmem=512 * 1024 * 1024
        )
        
        # Format for Hashcat Module 8900 (SCRYPT:N:r:p:base64_salt:base64_hash)
        b64_salt = base64.b64encode(salt_bytes).decode('utf-8')
        b64_hash = base64.b64encode(derived_key).decode('utf-8')
        hashcat_ready_string = f"SCRYPT:{N}:{r}:{p}:{b64_salt}:{b64_hash}"
        
        return b64_salt, hashcat_ready_string

    def _hash_argon2(self, password_plaintext, **kwargs):
        m = int(kwargs.get('m', 65536))
        t = int(kwargs.get('t', 2))
        p = int(kwargs.get('p', 1))
        dklen = int(kwargs.get('dklen', 32))
        salt_length = int(kwargs.get('salt_bytes', 16))
        
        # Let argon2-cffi handle its own salt generation and MCF formatting
        ph = Argon2PasswordHasher(
            memory_cost=m,
            time_cost=t,
            parallelism=p,
            hash_len=dklen,
            salt_len=salt_length,
            type=argon2.Type.ID
        )
        
        hashed_string = ph.hash(password_plaintext)
        
        # Extract the base64 salt directly from the generated MCF string
        parts = hashed_string.split('$')
        extracted_salt = parts[4] if len(parts) > 4 else ""
        
        return extracted_salt, hashed_string


# Example Usage:
if __name__ == "__main__":
    print("-" * 40)
    # Example using Bcrypt
    bcrypt_hasher = PasswordHasher(algorithm='bcrypt', rounds=12)
    salt_b, hash_b = bcrypt_hasher.generate_hash("mysecretpassword")
    print(f"Bcrypt:\n  Salt: {salt_b}\n  Hash: {hash_b}\n")

    # Example using PBKDF2 
    pbkdf2_hasher = PasswordHasher(algorithm='pbkdf2', iterations=120000, hash_algo='sha256', salt_bytes=16)
    salt_p, hash_p = pbkdf2_hasher.generate_hash("anothersecret")
    print(f"PBKDF2:\n  Salt (B64): {salt_p}\n  Hashcat Ready: {hash_p}\n")

    # Example using Scrypt 
    scrypt_hasher = PasswordHasher(algorithm='scrypt', N=16384, r=8, p=1, salt_bytes=16)
    salt_s, hash_s = scrypt_hasher.generate_hash("scrypt_password")
    print(f"Scrypt:\n  Salt (B64): {salt_s}\n  Hashcat Ready: {hash_s}\n")

    # Example using Argon2 
    argon2_hasher = PasswordHasher(algorithm='argon2', m=65536, t=3, p=4, salt_bytes=16)
    salt_a, hash_a = argon2_hasher.generate_hash("argon2_password")
    print(f"Argon2:\n  Salt (B64): {salt_a}\n  Hashcat Ready: {hash_a}\n")
    print("-" * 40)