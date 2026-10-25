import bcrypt

def hash_password(plain_text: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_text.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_text: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plain_text.encode('utf-8'), stored_hash.encode('utf-8'))

if __name__ == "__main__":
    test_pass = "SecurePass123!"
    hash1 = hash_password(test_pass)
    hash2 = hash_password(test_pass)
    
    print(f"Run 1: {hash1}")
    print(f"Run 2: {hash2}")
    print(f"Verification 1: {verify_password(test_pass, hash1)}")
    print(f"Verification 2: {verify_password(test_pass, hash2)}")