import sys
import os
import re
from threading import Thread
from typing import List

def getPassword(argv):
    if(len(argv) != 2):
        print("Cantidad de argumentos incorrectos, envie la contraseña")
        sys.exit(os.EX_USAGE)

    return argv[1]

def checkBruteForce(password, problems):
    if(len(password) < 16):
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


def main():
    password = getPassword(sys.argv)
    print(password)
    problems = list()

    thread = Thread(target = checkBruteForce, args = (password, problems))
    thread.start()
    thread.join()
    print(problems)


    return os.EX_OK

if __name__ == "__main__":
    sys.exit(main())
