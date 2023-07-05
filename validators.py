import os
import re
import time
import math
import signal
from threading import Thread, Event
from os.path import abspath

TIME_OUT = 30
MIN_PASS_LEN = 16
LEAKED_PASS_DIR = "leaked_passwords/"

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
        [r'\d{6}', "Digitos secuenciales"],                           # Sequential digits
        [r'(.)\1+', "Caracteres repetidos"],                          # Repeated characters
        [r'qwerty|asdf|zxcv|123', "Patrones de teclado"],             # Keyboard patterns
        [r'(?:password|contraseña|admin|123456)', "Palabras comunes de diccionario"], # Common dictionary words
        [r'\b(\w+)\s*\1\b', "Palabras repetidas"],                    # Repeated words
    ]

    for pattern in patterns:
        if re.search(pattern[0], password, re.IGNORECASE):
            problems.append(pattern[1])

    
def search_leaked_pass_in_file(password, problems, filepath, event):
    file1 = open(filepath, 'r', encoding="ISO-8859-1")
    leaked = False

    while True:
        line = file1.readline()

        if not line or event.is_set():
            break
        
        if line.rstrip() == password:
            leaked = True
            break

    if leaked:
        event.set()
        problems.append("Contraseña vulnerada")

    file1.close()

def is_leaked_pass(password, problems):
    event = Event()
    threads = list()
    for filename in os.listdir(LEAKED_PASS_DIR):
        if not filename.endswith("txt"):
            pass
        threads.append(Thread(target = search_leaked_pass_in_file, args = (password, problems, LEAKED_PASS_DIR + filename, event)))

    for x in threads:
        x.start()

    found = False
    for x in threads:
        x.join(TIME_OUT)

def calculate_entropy(password, problems):
    characters      = set(password)
    password_length = len(password)
    character_count = len(characters)
    
    entropy = password_length * math.log2(character_count)
    
    if entropy < 60:
        problems.append("La contraseña tiene baja entropía")
