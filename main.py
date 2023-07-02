import sys
import os
import signal
import validators
from threading import Thread
from threading import Lock
from typing import List
from tqdm import tqdm

validator_list = list()
completed_tasks = 0
pbar = tqdm(total=1, ncols = 75)

def get_password(argv):
    if(len(argv) != 2):
        print("Cantidad de argumentos incorrectos, envie la contraseña")
        sys.exit(os.EX_USAGE)

    return argv[1]

def done_handler(signum, frame):
    global pbar
    with Lock():
        pbar.update(1)

def execute_validator(validator, password, problems):
    
    #print("La existencia es dolor", validator)
    validator(password, problems)
    os.kill(os.getpid(), signal.SIGUSR1)
    #print("La existencia es dolor 2", validator)

def print_problems(problems):
    print("Problemas: ")
    for p in problems:
        print("\t", p)

def main():
    global validator_list
    global pbar
    signal.signal(signal.SIGUSR1, done_handler)

    password = get_password(sys.argv)
    problems = list()
    
    validator_list = [validators.check_brute_force, validators.validate_patterns, validators.is_leaked_pass, validators.calculate_entropy]
    pbar.total = len(validator_list)
    threads = list()
    for val in validator_list:
        threads.append(Thread(target = execute_validator, args = (val, password, problems)))

    try:
        # Start all threads
        for x in threads:
            x.start()

        # Wait for all of them to finish
        for x in threads:
            x.join()
    except KeyboardInterrupt:
        pass

    pbar.close()
    print_problems(problems)

    return os.EX_OK

if __name__ == "__main__":
    sys.exit(main())
