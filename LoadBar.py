from time import sleep
from os import get_terminal_size

TIME_FOR_EACH_LOGIN = 1.6

def load_bar(iteration, total, prefix='', i_end='\r', suffix='', decimals=1, length=100, fill='#'):
    percent = '{0:.{1}f}'.format(100 * (iteration / float(total)), decimals)
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix}<{bar}> {percent}% {suffix}', end=i_end)


def run_load_bar(i_prefix, i_suffix, i_length, i_items, sl_time):
    load_bar(0, i_length, prefix=i_prefix, i_end='\r', suffix=i_suffix, length=i_length)
    for i, _ in enumerate(i_items):
        sleep(sl_time)
        load_bar(i + 1, i_length, prefix=i_prefix, suffix=i_suffix, length=i_length)


def final_load_bar(i_prefix, i_suffix, i_length, i_items):
    load_bar(len(i_items), i_length, prefix=i_prefix, i_end='', suffix=i_suffix, length=i_length)


def exe():
    columns, _ = get_terminal_size()
    max_length = columns - 25
    items = list(range(0, max_length))
    length = len(items)
    sleep_time = TIME_FOR_EACH_LOGIN / max_length
    run_load_bar('', 'Login: Unknown', length, items, sleep_time)
    final_load_bar('', 'Login: ', length, items)


def writeResult(is_successful):
    if is_successful:
        print('Success')
    else:
        print('Failed')