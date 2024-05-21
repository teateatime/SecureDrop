import socket
import time
import os
from pathlib import Path
from cryptography.fernet import Fernet
import FileCredibility
import EncMsg
import encryption
import cryptography.exceptions

MAX_RECEIVE_SIZE = 1048575
TRANSFER_TIME = 10
TIMEOUT_INCREMENT = 0.2

def bigfile_and_user_continue(filesize) -> bool:
    dif = 0.9425
    transfer_time = (filesize * dif / 10000000)
    print(f'\nWARNING:\n\tThe sender is trying to send a file larger than one megabyte.\n'
          f'\t(encrypted_size = {(filesize * dif / 1000000):.2f} MB) This file transfer may take up to {transfer_time:.2f} seconds to complete!')
    ch = input('\tDo you have the space / would you like to receive this file (y/n)? ').strip().lower()
    while ch not in ('n', 'y'):
        print(f'\nWARNING:\n\tThe sender is trying to send a file larger than one megabyte.\n'
              f'\t(encrypted_size = {(filesize * dif / 1000000):.2f} MB) This file transfer may take up to {transfer_time:.2f} seconds to complete!')
        ch = input('\tDo you have the space / would you like to receive this file (y/n)? ').strip().lower()
    return ch == 'y'

def extrapolate_file_size(size_string):
    if 'size=' not in size_string:
        print('Something went wrong while getting sender\'s file size')
        return None
    try:
        return int(size_string.replace('size=', ''))
    except ValueError:
        print(f'Something went wrong while getting sender\'s file size. Debug: {size_string}')
        return None

def receive_file(hash, usr_email, timeout=30):
    IP = socket.gethostbyname(socket.gethostname())
    PORT = 4455
    ADDR = (IP, PORT)
    SIZE = 2048
    FORMAT = "utf-8"

    # Check for contacts
    try:
        FileCredibility.fullStop("contacts.txt")
        with open("contacts.txt", "r") as f:
            contact_data = f.readlines()
    except FileNotFoundError:
        print("No contacts found. Receiving a file requires having at least one contact. To add a contact, type 'add'\n")
        return

    # Create a TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(ADDR)
    except socket.error:
        print("Someone is already using the server. Try again later.\nReturning to SecureDrop menu.\n")
        return

    print(f"Server is listening for file transfer requests...\n"
          f"(If no file transfer requests come in {timeout} seconds, your connection will be timed out)")
    if timeout == 30:
        print('Timeout is set to 30 seconds by default. Change this by typing \'receive <int:time>\' for a custom timeout time.')

    server.settimeout(TIMEOUT_INCREMENT)
    connected = False
    while timeout >= 0:
        try:
            timeout -= TIMEOUT_INCREMENT
            server.listen()
            conn, addr = server.accept()
            print('\n')
            connected = True
            break
        except socket.timeout:
            if timeout >= 0:
                print(f'Returning to main menu in: {timeout:.1f} seconds', end='\r')

    if not connected:
        print("\nServer timed out. \nReturning to SecureDrop menu.\n")
        return

    try:
        contact = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print("\nLost connection to server. Returning to SecureDrop menu.\n")
        conn.close()
        return

    fernet = Fernet(encryption.calculateKey(hash)[0])
    contact_found = any(
        fernet.decrypt(line[:-1].encode()).decode() == contact
        for line in contact_data[1:]
    )

    if not contact_found:
        print("Someone who is not in your contacts list is trying to send you a file. Declining request and returning to SecureDrop menu.\n")
        conn.close()
        return

    conn.send(usr_email.encode(FORMAT))

    try:
        ready = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    if ready != "ready":
        print("The sender has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    c = input(f"\nContact '{contact}' is sending a file. Accept (y/n)? ").strip().lower()
    while c not in ('n', 'y'):
        print("Invalid input.")
        c = input(f"Contact '{contact}' is sending a file. Accept (y/n)? ").strip().lower()

    if c == 'n':
        conn.send(f"Contact '{usr_email}' has declined the transfer request.".encode(FORMAT))
        conn.close()
        print()
        return
    else:
        conn.send(f"Contact '{usr_email}' has accepted the transfer request.".encode(FORMAT))

    one_time_receiver_private_key = EncMsg.gen_receiver_key_file()
    if isinstance(one_time_receiver_private_key, int) and one_time_receiver_private_key == -1:
        print("Certificate authority declined to sign public key file.\nReturning to SecureDrop menu.\n")
        conn.close()
        return

    conn.send("r.pub".encode(FORMAT))

    FileCredibility.fullStop("r.pub")
    with open("r.pub", "r") as key_file:
        key_data = key_file.read()
    conn.send(key_data.encode(FORMAT))

    try:
        msg = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    conn.send("r.sig".encode(FORMAT))

    FileCredibility.fullStop("r.sig")
    with open("r.sig", "r") as sig_file:
        sig_data = sig_file.read()
    conn.send(sig_data.encode(FORMAT))

    try:
        msg = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    try:
        predicted_size = extrapolate_file_size(conn.recv(SIZE).decode(FORMAT))
        if predicted_size and predicted_size >= MAX_RECEIVE_SIZE:
            print(f"{contact} is encrypting a large file. This may take a moment...")
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    try:
        sender_public_key_filename = conn.recv(SIZE).decode(FORMAT)
        sender_public_key_data = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    FileCredibility.fullStop(sender_public_key_filename)
    with open(sender_public_key_filename, "w") as sender_public_key_file:
        sender_public_key_file.write(sender_public_key_data)
    FileCredibility.updateFiles([sender_public_key_filename])

    conn.send("Sender public key file has been successfully transferred.".encode(FORMAT))

    try:
        sender_sig_filename = conn.recv(SIZE).decode(FORMAT)
        sender_sig_data = conn.recv(SIZE)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    FileCredibility.fullStop(sender_sig_filename)
    with open(sender_sig_filename, "wb") as sender_sig_file:
        sender_sig_file.write(sender_sig_data)
    FileCredibility.updateFiles([sender_sig_filename])

    conn.send("Sender signature file has been transferred and authenticated.".encode(FORMAT))

    try:
        filename = conn.recv(SIZE).decode(FORMAT)
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    received_files_dir = Path('receivedFiles')
    received_files_dir.mkdir(exist_ok=True)
    filename = received_files_dir / filename

    try:
        filesize = extrapolate_file_size(conn.recv(SIZE).decode(FORMAT))
    except socket.error:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        conn.close()
        return

    if filesize is None:
        print('File size was not understood.\nReturning to SecureDrop menu.\n')
        conn.close()
        return

    big_file = filesize > MAX_RECEIVE_SIZE
    if big_file:
        if bigfile_and_user_continue(filesize):
            conn.send("y".encode(FORMAT))
            print('\nReceiving very large file...', end='\r')
            time.sleep(0.1)
            max_iterations = filesize // MAX_RECEIVE_SIZE
            with open(filename, "wb") as file:
                for iteration in range(max_iterations):
                    try:
                        file_data = conn.recv(MAX_RECEIVE_SIZE)
                    except socket.error:
                        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
                        conn.close()
                        return
                    file.write(file_data)
                    print(f'Receiving very large file: package {iteration} of {max_iterations + 1}', end='\r')
                try:
                    file_data = conn.recv(filesize % MAX_RECEIVE_SIZE + 10)
                except socket.error:
                    print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
                    conn.close()
                    return
                file.write(file_data)
                print(f'Receiving very large file: package {max_iterations + 1} of {max_iterations + 1}.')
        else:
            conn.send("n".encode(FORMAT))
            print(f'\nDeclining {contact}\'s file.\nReturning to SecureDrop menu.\n')
            conn.close()
            return
    else:
        conn.send("not_too_big".encode(FORMAT))
        with open(filename, "wb") as file:
            try:
                file_data = conn.recv(filesize)
            except socket.error:
                print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
                conn.close()
                return
            file.write(file_data)

    FileCredibility.updateFiles([filename])
    fnout = filename.name
    print(f"\n{fnout} has been received.\n")

    fn, extension = filename.stem, filename.suffix
    if big_file:
        size = int(os.path.getsize(filename)) + 1
        calc_mb = (size * 0.0009765625 / 1000)
        print(f'Beginning to decrypt {fnout} ({calc_mb:.2f} MB), approx: {(calc_mb * 0.0936037441 / 10):.1f} seconds')

    try:
        if EncMsg.decrypt_incoming_file(fn, extension, one_time_receiver_private_key):
            print(f"{fnout} has been decrypted.\n")
        else:
            print(f"{fnout} failed the decryption process.\n")
    except cryptography.exceptions.InvalidSignature:
        print('s.pub is a forgery!\nReturning to SecureDrop menu.\n')
        conn.close()
        return

    conn.send(f"{fnout} has been successfully transferred.".encode(FORMAT))
    conn.close()

if __name__ == '__main__':
    # Example usage
    receive_file('some_hash', 'user@example.com')
