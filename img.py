from os import get_terminal_size

CENTER_SIZE = 60
LONG_SIZE = 100
LONG_SPACE_SIZE = 109


def bye():
    print('Thank you for using Secure Drop')
    pass


def out():
    max_width = get_terminal_size().columns
    if max_width > LONG_SPACE_SIZE:
        out_long_space()
    elif max_width > LONG_SIZE:
        out_long()
    else:
        out_center()


def padding(size, max_width):
    num_spaces = (max_width - size) // 2
    return ' ' * num_spaces


def out_center():
    with open("images/img_center.txt", 'r') as img_file:
        line = img_file.readline().rstrip('\n')
        if not line:
            return
        while line:
            max_width = get_terminal_size().columns
            if max_width > CENTER_SIZE:
                print(padding(CENTER_SIZE, max_width), line)
            else:
                print(line[:get_terminal_size().columns])  # Cut off extra characters by getting terminal size
            line = img_file.readline().rstrip('\n')


def out_long_space():
    with open("images/img_long_space.txt", 'r') as img_file:
        line = img_file.readline().rstrip('\n')
        if not line:
            return
        while line:
            max_width = get_terminal_size().columns
            if max_width > LONG_SPACE_SIZE:
                print(padding(LONG_SPACE_SIZE, max_width), line)
            else:
                print(line[:get_terminal_size().columns])  # Cut off extra characters by getting terminal size
            line = img_file.readline().rstrip('\n')


def out_long():
    with open("images/img_long.txt", 'r') as img_file:
        line = img_file.readline().rstrip('\n')
        if not line:
            return
        while line:
            max_width = get_terminal_size().columns
            if max_width > LONG_SIZE:
                print(padding(LONG_SIZE, max_width), line)
            else:
                print(line[:get_terminal_size().columns])  # Cut off extra characters by getting terminal size
            line = img_file.readline().rstrip('\n')
