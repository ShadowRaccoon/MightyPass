import sys
import os
import signal
import time
import validators
import argparse
from threading import Thread, Lock, Semaphore
from tqdm import tqdm
from typing import List
from getpass import getpass

TIMEOUT = 180
OUTPUT_FILE = None

def read_args():
    # Seteamos parseador de argumentos
    parser = argparse.ArgumentParser(description='MightyPass', add_help=False)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Obtener ayuda sobre este comando y salir')
    parser.add_argument('-p', '--password', type=str, help='Pasar contraseña por parametro')
    parser.add_argument('-o', '--output', type=str, help='Pasar ruta de archivo de output')
    parser.add_argument('-t', '--timeout', type=int, help='Configurar el tiempo límite de ejecución')
    args = parser.parse_args()

    if args.password is None:
        password = getpass()
    else:
        password = args.password
    
    if args.output is not None:
        global OUTPUT_FILE
        OUTPUT_FILE = args.output
        #TODO: validate path

    if args.timeout is not None:
        global TIMEOUT
        TIMEOUT = args.timeout

    return password

# Handler de señal de fin del procesamiento de un validador
# Incrementa el progreso de la progress bar
def done_handler(signum, frame):
    global pbar
    global tasks_finished
    with Lock():
        tasks_finished+=1
        pbar.update(1)

def execute_validator(validator, password, problems):
    validator(password, problems)
    os.kill(os.getpid(), signal.SIGUSR1)


def print_problems(problems):
    global OUTPUT_FILE

    output = ""
    if len(problems) == 0:
        output += "Contraseña segura"
    else:
        output = "Problemas:"
        for p in problems:
            output += "\n\t" + p
    

    if OUTPUT_FILE is None:
        print(output)
    else:
        f = open(OUTPUT_FILE, "w")
        f.write(output)
        f.close()


def main():
    global validator_list
    global pbar
    global tasks_finished
    tasks_finished = 0
    # Seteamos el handler de las señales
    signal.signal(signal.SIGUSR1, done_handler)

    password = read_args()
    problems = list()
    
    # Seteamos validaciones a ejecutar
    validator_list = [validators.check_brute_force, validators.validate_patterns, validators.calculate_entropy, validators.is_leaked_pass]
    # Inicializamos la progress bar
    pbar = tqdm(total=len(validator_list), ncols = 75, desc="Procesando...", )

    threads = list()
    for val in validator_list:
        threads.append(Thread(target = execute_validator, args = (val, password, problems)))

    try:
        for x in threads:
            x.start()

        while(tasks_finished<len(validator_list)):
           pbar.update(0)   

        for x in threads:
            x.join()
    except KeyboardInterrupt:
        pass
    finally:
        pbar.close()

    print_problems(problems)

    return os.EX_OK

if __name__ == "__main__":
    sys.exit(main())
