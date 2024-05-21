from os import urandom, path as file_path
from hashlib import pbkdf2_hmac as hash_algo
from random import choices, randrange
import secrets
from string import ascii_uppercase as uppercase, ascii_lowercase as lowercase, digits
import FileCredibility
import encryption
import HashPasswords
import time

PICKLE_FILE = 'pickle.encrypted'
SALT_FILE = 'salt.encrypted'
PEPPER_FILE = 'pepper.encrypted'
PEPPER_LENGTH = 16  # Increased pepper length for better security
HASH_ALGORITHM = 'sha256'  # Using SHA-256 for hashing
ITERATIONS = 100000  # Number of iterations for key derivation

def writePsw(obj, unencoded_file):
    with open(unencoded_file + '.psw', 'wb') as f:
        f.write(obj)
    FileCredibility.updateFiles([unencoded_file + '.psw'])

def readPsw(unencoded_file):
    FileCredibility.fullStop(unencoded_file + '.psw')
    with open(unencoded_file + '.psw', 'rb') as f:
        obj = f.read()
    return obj

def newStore(password, pepper, unencoded_file):
    generate_pickle_list()
    password = password + pepper + randPickle()
    salt = urandom(32)
    key = hash_algo(HASH_ALGORITHM, password.encode('utf-8'), salt, ITERATIONS)
    writePsw(salt+key, unencoded_file)

def buildNew(password, salt):
    key = hash_algo(HASH_ALGORITHM, password.encode('utf-8'), salt, ITERATIONS)
    return key

def retrieve(unencoded_file):
    storage = readPsw(unencoded_file)
    return storage[:32], storage[32:]

def pass_compare_with_pickle(password, sal, pep, unencoded_file, email, return_dict) -> bool:
    FileCredibility.fullStop('userData.encrypted')
    with open('userData.encrypted', 'rb') as ud:
        enc_bytes_file = ud.read()
    for pickle in get_pickle_list():
        try:
            dec = HashPasswords.calcMaster(password, sal, pep, pickle)
            bytes_object = encryption.decrypt_bytes(enc_bytes_file, dec)
            fname, femail = bytes_object.decode().split('\n')
            if email == femail:
                return_dict[0] = (True, fname, femail)
                return
        except Exception as e:
            pass
    return_dict[0] = (False, '', '')

def pass_compare(password, pepper, pickle, unencoded_file) -> bool:
    password = password + pepper + pickle
    storage = retrieve(unencoded_file)
    salt_from_storage = storage[0]
    org_key = storage[1]
    key_check = hash_algo(
        HASH_ALGORITHM,
        password.encode('utf-8'),  # Convert the password to bytes
        salt_from_storage,
        ITERATIONS
    )
    return org_key == key_check

def generatePepper(str_len):  # rand str of len @param::str_len, [ABCD...]+[abcd...]
    return ''.join(secrets.choice(uppercase + lowercase + digits) for _ in range(str_len))

def randPickle():
    pl = get_pickle_list()
    return pl[randrange(0, 9)]

def get_pickle_list():
    if not file_path.exists(PICKLE_FILE):
        generate_pickle_list()
    with open(PICKLE_FILE, 'r') as pickle:
        pickle_list = pickle.readline()
    chunks, chunk_size = len(pickle_list), 6
    return [pickle_list[i:i+chunk_size] for i in range(0, chunks, chunk_size)]

def generate_pickle_list():
    if not file_path.exists(PICKLE_FILE):
        with open(PICKLE_FILE, 'w') as f_pickle:
            for _ in range(10):
                f_pickle.write(''.join(secrets.choice(uppercase + lowercase + digits) for _ in range(6)))
        FileCredibility.updateFiles([PICKLE_FILE])
        time.sleep(0.1)

def condiments():
    generate_pickle_list()
    salt = urandom(32)
    pepper = generatePepper(PEPPER_LENGTH).encode()
    pickle = randPickle()
    saveCondiments(salt, pepper)
    return salt, pepper, pickle

def saveCondiments(s, p):
    with open(SALT_FILE, 'wb') as sout:
        sout.write(s)
    with open(PEPPER_FILE, 'wb') as pout:
        pout.write(p)
    FileCredibility.updateFiles([SALT_FILE, PEPPER_FILE])

def calcMaster(ipas, isal, ipep, ipic):
    password = ipas + ipep + ipic.encode()
    out = hash_algo(
        HASH_ALGORITHM,
        password,  # Convert the password to bytes
        isal,
        ITERATIONS
    )
    return out

def calcPepperHash(password, s, p):
    return password + p

def getCondiments():
    FileCredibility.fullStop(SALT_FILE)
    FileCredibility.fullStop(PEPPER_FILE)
    with open(SALT_FILE, 'rb') as out:
        sal = out.read()
    with open(PEPPER_FILE, 'rb') as out:
        pep = out.read()
    return sal, pep
