import bcrypt
import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt,lmhash
from argon2 import PasswordHasher
from Crypto.Hash import MD4
from argon2.exceptions import VerifyMismatchError,VerificationError
from itertools import permutations


def crack_pass(h,algo):
    h = h.strip()
    ph = PasswordHasher()
    print("Please select cracking mode : \n 1. filtered-Wordlist Mode(filtered by length of password)  \n 2. self-generate-wordlist Mode (Customizable) \n 3. Default Mode ")
    
    mode = input("Enter your Mode : ")

    if mode=="1":
        pwd_len = int(input("Enter length of password : "))
        count = 0
        not_found = True
        with open("/usr/share/wordlists/rockyou.txt","r",encoding="latin-1") as f:
            for line in f:
                gs_paswd = line.strip()
                if len(gs_paswd)==pwd_len:
                    count+=1

                    if algo=="Bcrypt":
                        if bcrypt.checkpw(gs_paswd.encode("utf-8"),h.encode("utf-8")):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="MD5":
                        if hashlib.md5(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="MD4":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode())
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="NTLM":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode("utf-16le"))
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="LM":
                        try:
                            if lmhash.verify(gs_paswd,h.lower()):
                                print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                                print("Total attempts : ",count)
                                not_found = False
                                break
                            else:
                                print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                        
                        except UnicodeEncodeError:
                            continue
                        
                    elif algo=="SHA256":
                        if hashlib.sha256(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="SHA512":
                        if hashlib.sha512(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA1":
                        if hashlib.sha1(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="MD5-Crypt":
                        if md5_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA256-Crypt":
                        if sha256_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA512-Crypt":
                        if sha512_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="Argon2":
                        try:
                            ph.verify(h,gs_paswd)
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        except (VerifyMismatchError,VerificationError):
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                else:
                    continue
            if not_found:
                print(f"\n\033[1;91m [Password Not Found],\033[0m please try another wordlist...")

    elif mode=="2":
        print("Enter your words \n type /e when complete")
        word = []
        while True:
            wrd = input(">> ")
            if wrd.lower()=="/e":
                break
            word.append(wrd)

        print("Your wordlist : ", word)
        count = 0
        not_found = True
        for i in range(1, len(word)+1):
            if not_found:
                for p in permutations(word, i):
                    gs_paswd = "".join(p)
                    count+=1

                    if algo=="Bcrypt":
                        if bcrypt.checkpw(gs_paswd.encode("utf-8"),h.encode("utf-8")):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="MD5":
                        if hashlib.md5(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="MD4":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode())
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="NTLM":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode("utf-16le"))
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                    elif algo=="LM":
                        if lmhash.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA256":
                        if hashlib.sha256(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA512":
                        if hashlib.sha512(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA1":
                        if hashlib.sha1(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="MD5-Crypt":
                        if md5_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA256-Crypt":
                        if sha256_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="SHA512-Crypt":
                        if sha512_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                    elif algo=="Argon2":
                        ph = PasswordHasher()
                        try:
                            ph.verify(h,gs_paswd)
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        except (VerifyMismatchError,VerificationError):
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
            else:
                break

        if not_found:
            print(f"\n\033[1;91m [Password Not Found],\033[0m please try another combinations...")
        
    elif mode=="3":
        count = 0
        not_found = True
        with open("/usr/share/wordlists/rockyou.txt","r",encoding="latin-1") as f:
            for line in f:
                    
                gs_paswd = line.strip()
                count+=1
                
                if algo=="Bcrypt":
                        if bcrypt.checkpw(gs_paswd.encode("utf-8"),h.encode("utf-8")):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                elif algo=="MD5":
                    if hashlib.md5(gs_paswd.encode()).hexdigest() == h.lower():
                        print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                        print("Total attempts : ",count)
                        not_found = False
                        break
                    else:
                        print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                
                elif algo=="NTLM":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode("utf-16le"))
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="LM":
                        if lmhash.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="MD4":
                        hsh = MD4.new()
                        hsh.update(gs_paswd.encode())
                        if hsh.hexdigest().lower() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                
                elif algo=="SHA256":
                        if hashlib.sha256(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                
                elif algo=="SHA512":
                        if hashlib.sha512(gs_paswd.encode()).hexdigest() == h.lower():
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="SHA1":
                    if hashlib.sha1(gs_paswd.encode()).hexdigest() == h.lower():
                        print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                        print("Total attempts : ",count)
                        not_found = False
                        break
                    else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
                    
                
                elif algo=="MD5-Crypt":
                        if md5_crypt.verify(gs_paswd,h):
                            print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                            print("Total attempts : ",count)
                            not_found = False
                            break
                        else:
                            print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="SHA256-Crypt":
                    if sha256_crypt.verify(gs_paswd,h):
                        print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                        print("Total attempts : ",count)
                        not_found = False
                        break
                    else:
                        print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="SHA512-Crypt":
                    if sha512_crypt.verify(gs_paswd,h):
                        print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                        print("Total attempts : ",count)
                        not_found = False
                        break
                    else:
                        print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)

                elif algo=="Argon2":
                    ph = PasswordHasher()
                    try:
                        ph.verify(h,gs_paswd)
                        print(f"\033[1;92m[SUCCESS]\033[0m Password matched : ",f"\033[1;92m{gs_paswd}\033[0m")
                        print("Total attempts : ",count)
                        not_found = False
                        break
                    except (VerifyMismatchError,VerificationError):
                        print(f"\033[91m[FAILED]\033[0m Password not matched! : ",gs_paswd)
            
            if not_found:
                print(f"\n\033[1;91m [Password Not Found],\033[0m please try another wordlist...")
        


    else:
        print(f"\n\033[1;91m Invalid Mode\033[0m\n Try again...")
        crack_pass(h,algo)