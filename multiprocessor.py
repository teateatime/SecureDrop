import multiprocessing
import LoadBar
from HashPasswords import pass_compare_with_pickle
import time
import socket

def authenticate_login(pswd, sal, pep, file, email):
    print('Creating login token...')
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    p1 = multiprocessing.Process(target=LoadBar.exe, args=[])
    p2 = multiprocessing.Process(target=pass_compare_with_pickle, args=(pswd, sal, pep, file, email, return_dict))
    p1.start()
    p2.start()
    p1.join()
    p2.join()

    status, name, email = return_dict.values()[0]
    LoadBar.writeResult(status)
    return status, name, email

def action(run_flag, max_time):
    while run_flag.value and max_time > 0:
        print(f'Returning to main menu in: {max_time:.2f} seconds', end='\r')
        time.sleep(0.1)
        max_time -= 0.1
    print(f'Returning to main menu in: 0.00 seconds')

def timer(run_flag, server, timeout, return_dict):
    server.settimeout(timeout)
    try:
        server.listen()
        run_flag.value = False
        return_dict[0] = server.accept()
    except socket.timeout:
        run_flag.value = False
        print("\nServer timed out. \nReturning to SecureDrop menu.\n")

def receiveFileTimeout(server, timeout):
    run_flag = multiprocessing.Value('I', True)
    manager = multiprocessing.Manager()
    return_dict = manager.dict()

    print_time = multiprocessing.Process(target=action, args=(run_flag, timeout))
    request_connection = multiprocessing.Process(target=timer, args=(run_flag, server, timeout, return_dict))

    print_time.start()
    request_connection.start()

    print_time.join()
    request_connection.join()

    if run_flag.value:
        return return_dict.get(0)
    return None
