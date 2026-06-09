from hash_identifier import identify_hash
from crack import crack_pass

if __name__ == "__main__":
    while True:

        banner = r'''
                                                                                          __    __
         _______  _____       ___      _______  _         _____   _                    __|  |__|  |__ 
        |  ____/ |  _  \     / _ \    |  ____/ | | /\    |_   _| | |      ____        |__   ____   __|
        | |      | |_) /    / /_\ \   | |      | |/ /      | |   | |__   | . /         __|  |___| |__
        | |_____ |  __ \   /  ___  \  | |_____ |   \       | |   |  _ \  |  /_        |__    ___   __| 
        |______/ |_|  \_\ /__/   \__\ |______/ |_|\_\      |_|   |_| \_\ |____|          |__|   |__|
        
        '''
        
        print(f"\033[94m{banner}\033[0m")
        

        hash_pwd = input(f"\033[1;91m Enter Your Hash : \033[0m")
        if hash_pwd.lower() =="exit":
            exit()
        algo = identify_hash(hash_pwd)
        if algo:
            print(f"\033[1;92m{algo}\033[0m")
            
        if algo == "Algorithm : Bcrypt":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"Bcrypt")
        
        elif algo == "Possible Algorithms : MD5/ MD4 / NTLM / LM":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                alg = input("Enter the Algorithm [MD5 / MD4 / NTLM / LM] : ").strip()
                if alg.upper()=="MD5":
                    crack_pass(hash_pwd,"MD5")
                elif alg.upper()=="NTLM":
                    crack_pass(hash_pwd,"NTLM")
                elif alg.upper()=="LM":
                    crack_pass(hash_pwd,"LM")
                elif alg.upper()=="MD4":
                    crack_pass(hash_pwd,"MD4")
                    
                else:
                    print("Please enter valid algorithm")
                    continue

        elif algo == "Algorithm : SHA256":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"SHA256")

        elif algo == "Algorithm : SHA512":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"SHA512")

        elif algo == "Algorithm : SHA1":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"SHA1")

        elif algo == "Algorithm : MD5-Crypt":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"MD5-Crypt")

        elif algo == "Algorithm : SHA256-Crypt":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"SHA256-Crypt")

        elif algo == "Algorithm : SHA512-Crypt":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"SHA512-Crypt")

        elif algo == "Algorithm : Argon2":
            inp = input("Do you want to crack pass [y/n] : ")
            if inp.lower()=="y":
                crack_pass(hash_pwd,"Argon2")
