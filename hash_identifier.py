def identify_hash(h):
    h = h.strip()

    if h.startswith(("$2a$","$2b$","$2y$")):
        return "Algorithm : Bcrypt"
    
    elif h.startswith("$1$"):
        return "Algorithm : MD5-Crypt"

    elif h.startswith("$5$"):
        return "Algorithm : SHA256-Crypt"

    elif h.startswith("$6$"):
        return "Algorithm : SHA512-Crypt"


    elif h.startswith(("$argon2i$", "$argon2d$", "$argon2id$")):
        return "Algorithm : Argon2"
    
    else:
        hex_char = "0123456789abcdefABCDEF"
        is_hash = True
        for letter in h:
            if letter not in hex_char:
                is_hash =False
                break

        if is_hash:
            if len(h)==32:
                return "Possible Algorithms : MD5/ MD4 / NTLM / LM"
            elif len(h)==40:
                return "Algorithm : SHA1"
            elif len(h)==64:
                return "Algorithm : SHA256"
            elif len(h)==128:
                return "Algorithm : SHA512"
            else:
                print(f"\033[91m No Algorithm Found, Please check the length of hash\033[0m")
        else:
            print( f"\033[91m Invalid Hash\033[0m" )
