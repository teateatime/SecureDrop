import reset
import time
import os

def unpack():
    """
    Simulate an unpacking process with a progress indication.
    """
    print('unpacking', end='\r')
    reset.reset(printable=False)
    for i in range(3):
        print(f'unpacking{"." * (i + 1)}', end='\r')
        time.sleep(0.6 if i == 1 else 0.8 if i == 0 else 1.4)
    print('unpacking complete.')

def is_packed() -> bool:
    """
    Check if the 'debug.conf' file exists, remove it if it does, and return True.
    Return False if the file does not exist.
    """
    if os.path.exists('debug.conf'):
        os.remove('debug.conf')
        return True
    return False
