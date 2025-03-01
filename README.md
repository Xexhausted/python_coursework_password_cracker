---

# Password Cracker  

This is a simple password cracking tool that checks a given hash against a wordlist to find the original password.  

## How It Works  

1. The user inputs a hash value to crack.  
2. The program detects the hash type (MD5, SHA-1, SHA-256, or SHA-512).  
3. It loads a wordlist and hashes each word using the detected hash type.  
4. If a match is found, the original password is displayed.  
5. If no match is found, it informs the user that the password is not in the wordlist.  

## Supported Hashes  

- MD5  
- SHA-1  
- SHA-256  
- SHA-512  

## Requirements  

- Python 3  
- `bcrypt` library (install using `pip install bcrypt`)  
- A wordlist (e.g., `rockyou.txt`)  

## Usage  

1. Run the script:  
   ```bash
   python main.py
   ```  
2. Enter the hash you want to crack.  
3. The program will attempt to find the password using the wordlist.  

## Wordlist  

By default, the script uses:  
```
path_to_your_wordlist
```
You can change this path in the script.  

## Notes  

- The tool does **not** support salted hashes.  
- If the wordlist file is missing, an error will be shown.  

---
