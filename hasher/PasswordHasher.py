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
    handling the specifics of salt generation and parameter passing for each.
    """

    def __init__(self, algorithm, **kwargs):
        """
        Initializes the PasswordHasher instance with a specific algorithm.

        Args:
            algorithm (str): The name of the hashing algorithm to use.
                             Supported algorithms: 'pbkdf2', 'bcrypt', 'scrypt', 'argon2'.
            **kwargs: Algorithm-specific parameters.
                      - For 'pbkdf2': 'iterations', 'dklen', 'hash_algo', 'salt_bytes'.
                      - For 'bcrypt': 'rounds'.
                      - For 'scrypt': 'N', 'r', 'p', 'dklen', 'salt_bytes'.
                      - For 'argon2': 'm', 't', 'p', 'dklen', 'salt_bytes'.
        """
        self.algorithm = algorithm.lower()
        self.params = kwargs

        # Dictionary to map algorithm names to their hashing methods.
        self.hasher_methods = {
            'pbkdf2_sha256': self._hash_pbkdf2,
            'bcrypt': self._hash_bcrypt,
            'scrypt': self._hash_scrypt,
            'argon2': self._hash_argon2
        }

        if self.algorithm not in self.hasher_methods:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def generate_hash(self, password_plaintext):
        """
        Generates a salted password hash using the specified algorithm.

        Args:
            password_plaintext (str): The plaintext password to hash.

        Returns:
            tuple: A tuple containing the salt and the generated hash.
                   The format of the salt depends on the algorithm.
        """
        hasher_func = self.hasher_methods[self.algorithm]
        return hasher_func(password_plaintext, **self.params)

    def _generate_salt(self, length):
        """Generates a random salt of a given length (bytes)."""
        return os.urandom(length)

    def _hash_pbkdf2(self, password_plaintext, **kwargs):
        """Hashes a password using PBKDF2."""
        iterations = int(kwargs.get('iterations', 100000))
        dklen = int(kwargs.get('dklen', 32))
        hash_algo = kwargs.get('hash_algo', 'sha256')
        salt_length = int(kwargs.get('salt_bytes', 16))
        salt_bytes = self._generate_salt(length=salt_length)

        hashed = hashlib.pbkdf2_hmac(
            hash_name=hash_algo,
            password=password_plaintext.encode('utf-8'),
            salt=salt_bytes,
            iterations=iterations,
            dklen=dklen
        )
        return salt_bytes.hex(), hashed.hex()

    def _hash_bcrypt(self, password_plaintext, **kwargs):
        """Hashes a password using Bcrypt."""
        rounds = int(kwargs.get('rounds', 12))
        salt_bytes = bcrypt.gensalt(rounds=rounds)

        hashed = bcrypt.hashpw(password_plaintext.encode('utf-8'), salt_bytes)
        return salt_bytes.decode('utf-8'), hashed.decode('utf-8')

    def _hash_scrypt(self, password_plaintext, **kwargs):
        """Hashes a password using Scrypt."""
        N = int(kwargs.get('N', 16384))
        r = int(kwargs.get('r', 8))
        p = int(kwargs.get('p', 1))
        dklen = int(kwargs.get('dklen', 32))
        salt_length = int(kwargs.get('salt_bytes', 16))
        salt_bytes = self._generate_salt(length=salt_length)

        hashed = hashlib.scrypt(
            password=password_plaintext.encode('utf-8'),
            salt=salt_bytes,
            n=N, r=r, p=p,
            dklen=dklen
        )
        return salt_bytes.hex(), hashed.hex()

    def _hash_argon2(self, password_plaintext, **kwargs):
        """Hashes a password using Argon2."""
        m = int(kwargs.get('m', 65536))
        t = int(kwargs.get('t', 2))
        p = int(kwargs.get('p', 1))
        dklen = int(kwargs.get('dklen', 32))
        salt_length = int(kwargs.get('salt_bytes', 16))
        salt_bytes = self._generate_salt(length=salt_length)
        
        ph = Argon2PasswordHasher(
            memory_cost=m,
            time_cost=t,
            parallelism=p,
            hash_len=dklen,
            type=argon2.Type.ID
        )
        
        hashed_string = ph.hash(password_plaintext, salt=base64.b64encode(salt_bytes))
        return base64.b64encode(salt_bytes).decode('utf-8'), hashed_string

# Example Usage:
if __name__ == "__main__":
    # Example using Bcrypt
    bcrypt_hasher = PasswordHasher(algorithm='bcrypt', rounds=14)
    salt_b, hash_b = bcrypt_hasher.generate_hash("mysecretpassword")
    print(f"Bcrypt:\n  Salt: {salt_b}\n  Hash: {hash_b}\n")

    # Example using PBKDF2 with custom salt length
    pbkdf2_hasher = PasswordHasher(algorithm='pbkdf2', iterations=200000, hash_algo='sha512', salt_bytes=32)
    salt_p, hash_p = pbkdf2_hasher.generate_hash("anothersecret")
    print(f"PBKDF2:\n  Salt: {salt_p}\n  Hash: {hash_p}\n")
    print(f"  Salt length: {len(bytes.fromhex(salt_p))} bytes\n")

    # Example using Scrypt with custom salt length and a safer N value
    scrypt_hasher = PasswordHasher(algorithm='scrypt', N=2**14, r=8, p=1, salt_bytes=24)
    salt_s, hash_s = scrypt_hasher.generate_hash("scrypt_password")
    print(f"Scrypt:\n  Salt: {salt_s}\n  Hash: {hash_s}\n")
    print(f"  Salt length: {len(bytes.fromhex(salt_s))} bytes\n")

    # Example using Argon2 with custom salt length
    argon2_hasher = PasswordHasher(algorithm='argon2', m=16384, t=4, p=2, salt_bytes=16)
    salt_a, hash_a = argon2_hasher.generate_hash("argon2_password")
    print(f"Argon2:\n  Salt: {salt_a}\n  Hash: {hash_a}\n")
    print(f"  Salt length: {len(base64.b64decode(salt_a))} bytes\n")
