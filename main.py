import hashlib
import bcrypt

# Define supported hash functions
SUPPORTED_HASHES = {
    "md5": lambda x: hashlib.md5(x.encode()).hexdigest(),
    "sha1": lambda x: hashlib.sha1(x.encode()).hexdigest(),
    "sha256": lambda x: hashlib.sha256(x.encode()).hexdigest(),
    "sha512": lambda x: hashlib.sha512(x.encode()).hexdigest(),
}

def hash_password(password, algorithm):
    """Hash a given password using the specified algorithm."""
    if algorithm in SUPPORTED_HASHES:
        return SUPPORTED_HASHES[algorithm](password)
    elif algorithm == "bcrypt":
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def detect_hash_type(hash_value):
    """Detect the hash type based on its length."""
    hash_length = len(hash_value)
    if hash_length == 32:
        return "md5"
    elif hash_length == 40:
        return "sha1"
    elif hash_length == 64:
        return "sha256"
    elif hash_length == 128:
        return "sha512"
    else:
        return None

def crack_hash(hash_to_crack, wordlist_file):
    """Try to crack the given hash using a wordlist."""
    hash_type = detect_hash_type(hash_to_crack)
    if not hash_type:
        print("[-] Unsupported hash type.")
        return

    print(f"[+] Detected Hash Type: {hash_type}")
    print("[+] Starting Password Cracking...")

    try:
        with open(wordlist_file, "r", encoding="ISO-8859-1", errors="ignore") as file:
            for word in file:
                word = word.strip()
                if hash_password(word, hash_type) == hash_to_crack:
                    print(f"[+] Password Found: {word}")
                    return word
        print("[-] Password not found in the wordlist.")
    except FileNotFoundError:
        print("[-] Wordlist file not found!")

# Example Usage:
if __name__ == "__main__":
    hash_to_crack = input("Enter the hash to crack: ").strip()
    wordlist_file = "path_to_your_wordlist"
    crack_hash(hash_to_crack, wordlist_file)
