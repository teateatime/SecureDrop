import time
import os
from cryptography.fernet import Fernet
import SecureDrop

ENCODING = 'latin1'
NEWFILE = '\n'

def gen_dependencies_key():
    key = Fernet.generate_key()
    with open('dependencie_key.encrypted', 'wb') as out:
        out.write(key)

def get_dependencies_key():
    with open('dependencie_key.encrypted', 'rb') as fin:
        return Fernet(fin.read())

def save_dependencies(dependencies):
    fernet = get_dependencies_key()
    with open('dependencies.enc', 'wb') as out:
        out.write(fernet.encrypt(dependencies.encode()))

def get_dependencies():
    try:
        fernet = get_dependencies_key()
        with open('dependencies.enc', 'rb') as fin:
            return fernet.decrypt(fin.read()).decode()
    except:
        return ''

def writeTime(file_path):
    updated = ''
    for line in get_dependencies().split(NEWFILE):
        if '->' in line and line[0:line.index('->')] != file_path:
            updated += line + NEWFILE
    updated += (file_path + '->' + getTime(file_path))
    save_dependencies(updated)

def getTime(file_path):
    return time.ctime(os.path.getmtime(file_path))

def timeEquates(file_path):
    if os.path.exists('dependencies.enc'):
        try:
            file = get_dependencies().split(NEWFILE)
            for line in file:
                fname, value = line.split('->')
                if fname == file_path:
                    return getTime(file_path) == value
        except:
            print('throw => dependencies_file_corruption | Exiting.')
            pass
    return False

def updateFiles(files):
    if os.path.exists('dependencies.enc'):
        for file in files:
            writeTime(file)

def fullStop(file):
    if os.path.exists(file):
        status = timeEquates(file)
        if not status:
            SecureDrop.leave(True)
            print(f"throw => '{file}' has been tampered with. Exiting program.")
            quit()

def VerifyFiles() -> bool:
    print('Verifying authenticity of internal files', end='\r')
    file = get_dependencies().split(NEWFILE)
    iteration = 0
    for line in file:
        try:
            fullStop(line.split('->')[0])
            print(f'Verifying authenticity of internal files ({iteration}/{len(file)})', end='\r')
            iteration += 1
            time.sleep(0.03)
        except:
            print(f'throw => could not extract file data from line!\nExiting...')
            quit()

    time.sleep(0.05)
    print(f'Verifying authenticity of internal files ({len(file)}/{len(file)})', end='\r')
    time.sleep(0.07)
    print('                                                                                                     ', end='\r')
    time.sleep(0.02)
    return True
