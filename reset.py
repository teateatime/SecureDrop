import os
import shutil
from pathlib import Path
import FileCredibility

# Constants
PYTHON_FILES = [
    'CertificateAuthority.py', 'ECDH.py', 'EncMsg.py', 'encryption.py', 
    'FileCredibility.py', 'HashPasswords.py', 'img.py', 'LoadBar.py', 
    'multiprocessor.py', 'receiver.py', 'reset.py', 'SecureDrop.py', 'sender.py'
]

FILES_TO_REMOVE = [
    'contacts.txt', 'sym_file.encoded', 'r.pub', 'r.sig', 's.pub', 's.sig'
]

CERTIFICATE_FILES = ['certs/ca.pri', 'certs/ca.pub']

SELF_IMG_FILES = ['images/img_center.txt', 'images/img_long_space.txt', 'images/img_long.txt']

def reset(printable=True):
    """
    Reset the environment by removing specific files and generating a new dependencies key.
    """
    # List all files in the current directory
    files = Path('.').iterdir()

    # Remove files with specific extensions
    for file in files:
        if file.suffix in {'.zok', '.encrypted'}:
            file.unlink()

    # Remove specific files
    for file in FILES_TO_REMOVE:
        try:
            Path(file).unlink()
        except FileNotFoundError:
            pass

    # Generate dependencies key and ensure the dependencies file is empty
    FileCredibility.gen_dependencies_key()
    dependencies_file = Path('dependencies.enc')
    dependencies_file.touch(exist_ok=True)
    dependencies_file.write_text('')

    # Update the list of files for file credibility
    FileCredibility.updateFiles(CERTIFICATE_FILES + PYTHON_FILES + SELF_IMG_FILES)

    if printable:
        print("reset")

if __name__ == '__main__':
    reset()
