import re
import time
import math

MIN_PASS_LEN = 16

def check_brute_force(password, problems):
    if(len(password) < MIN_PASS_LEN):
        problems.append("Tiene pocos carácteres")

    # Verificar si la contraseña contiene solo letras o solo números
    if password.isalpha():
        problems.append("Contiene solo letras")

    if(password.isdigit()):
        problems.append("Contiene solo números")

    # Verificar si la contraseña es una secuencia de números
    if password.isdigit() and password in "1234567890":
        problems.append("Contiene secuencia de números")

    # Verificar si la contraseña es una secuencia de letras
    if password.isalpha() and password.lower() in "abcdefghijklmnopqrstuvwxyz":
        problems.append("Tiene secuencia de letras")

    # Verificar si la contraseña contiene caracteres especiales
    if not re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~" + r'"]', password):
        problems.append("No tiene carácteres especiales")

def validate_patterns(password, problems):
    patterns = [
        [r'\d{6}', "Sequential digits"],                           # Sequential digits
        [r'(.)\1+', "Repeated characters"],                        # Repeated characters
        [r'qwerty|asdf|zxcv|123', "Keyboard patterns"],            # Keyboard patterns
        [r'(?:password|admin|123456)', "Common dictionary words"], # Common dictionary words
        [r'[^\w\s]', "Special characters"],                        # Special characters
        [r'\b(\w+)\s+\1\b', "Repeated words"],                     # Repeated words
        [r'\b(\w{1,2})\1+\b', "Repeated short words"]              # Repeated short words
    ]

    for pattern in patterns:
        if re.search(pattern[0], password, re.IGNORECASE):
            problems.append(pattern[1])
    


def is_leaked_pass(password, problems):
    # TODO multiple files
    # files = [file for file in file.file("leaked_passwords/*.txt")]
    # leaked = False
    # for file_name in files:
    #     with io.open(file_name, 'r') as txt_file:
    #         while True:
    #             line = txt_file.readline()
    #             if not line:
    #                 break
                        
    #             if line.rstrip() == password:
    #                 leaked = True
    #                 break
    
    file1 = open("leaked_passwords/worst_passwords.txt", 'r')
    leaked = False
    
    while True:
        line = file1.readline()

        if not line:
            break
        
        if line.rstrip() == password:
            leaked = True
            break

    if leaked:
        problems.append("Contraseña vulnerada en ")

    file1.close()

def calculate_entropy(password, problems):
    characters      = set(password)
    password_length = len(password)
    character_count = len(characters)
    
    entropy = password_length * math.log2(character_count)
    
    if entropy < 60:
        problems.append("La contraseña tiene baja entropía")


