import socket
import os
from cryptography.fernet import Fernet
import encryption
import EncMsg
import FileCredibility
import cryptography.exceptions

EXIT_ARR = ['q', 'quit', 'exit', 'leave', 'disconnect', 'returntomenu', 'returntosecuredrop']
MAX_RECEIVE_SIZE = 1048575  # 1,048,575 bytes (approx 1 MB)

def wish_to_leave(filename):
    if filename.lower().replace(' ', '') in EXIT_ARR:
        ch = input(f'You entered {filename}, do you want to leave "send" and return to the main menu in Secure Drop? (y/n): ').lower()
        while ch != 'y' and ch != 'n':
            ch = input(f'You entered {filename}, do you want to leave "send" and return to the main menu in Secure Drop? (y/n): ').lower()
        return ch == 'y'
    return False

def get_file_size(file_name):
    return int(os.path.getsize(file_name)) + 1

def predict_file_size(file_name):
    return int(os.path.getsize(file_name) * 1.33) + 1

def send_file(hash, usr_email):
    # Server info
    IP = socket.gethostbyname(socket.gethostname())
    PORT = 4455
    ADDR = (IP, PORT)
    FORMAT = "utf-8"
    SIZE = 1024

    # Verify contacts
    try:
        FileCredibility.fullStop("contacts.txt")
        with open("contacts.txt", "r") as f:
            contact_data = f.readlines()
    except:
        print("No contacts found. Sending a file requires having at least one contact. To add a contact, type 'add'.\n")
        return

    # Create a TCP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client.connect(ADDR)
    except:
        print("There are no contacts online. Returning to SecureDrop menu.\n")
        client.close()
        return

    # Send user email to the server
    client.send(usr_email.encode(FORMAT))

    try:
        # Get online contact from server
        online_contact = client.recv(SIZE).decode(FORMAT)
    except:
        print("\nLost connection to server. Returning to SecureDrop menu.\n")
        client.close()
        return

    # Verify if the online contact is in the contact list
    fernet = Fernet(encryption.calculateKey(hash)[0])
    contact_found = any(fernet.decrypt(line[:-1].encode()).decode() == online_contact for line in contact_data[1::2])

    if not contact_found:
        print("Someone who is not in your contacts is trying to receive your file. Returning to SecureDrop menu.\n")
        client.close()
        return

    print(f"The following contact is online:\n  * {online_contact}")

    contact = input("\nPlease enter the email of the contact you wish to send a file to: ")

    contact_found = any(fernet.decrypt(line[:-1].encode()).decode() == contact for line in contact_data[1::2])

    if not contact_found:
        print("Contact not found in contacts list. Returning to SecureDrop menu.\n")
        client.close()
        return

    if online_contact != contact:
        print("That contact is not online. Returning to SecureDrop menu.\n")
        client.close()
        return

    filename = input("Please enter the name of the file you wish to send: ")
    if wish_to_leave(filename):
        client.close()
        return

    while not os.path.exists(filename):
        print(f"Cannot find file '{filename}'.\nYou may enter 'quit' or 'exit' to leave this prompt.")
        filename = input("Please re-enter the name of the file you wish to send: ")
        if wish_to_leave(filename):
            client.close()
            return

    FileCredibility.updateFiles([filename])

    client.send("ready".encode(FORMAT))
    print("\nWaiting for contact to accept file transfer...")

    try:
        # Receive message from server about accepted transfer request
        msg = client.recv(SIZE).decode(FORMAT)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    if contact not in msg:
        print("The response was not from your contact. Returning to SecureDrop menu.\n")
        client.close()
        return

    if "declined" in msg:
        print("Returning to SecureDrop menu.\n")
        client.close()
        return

    try:
        key_filename = client.recv(SIZE).decode(FORMAT)
        key_data = client.recv(SIZE).decode(FORMAT)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    with open(key_filename, "w") as key_file:
        key_file.write(key_data)
    FileCredibility.updateFiles([key_filename])

    client.send("Receiver public key file has been successfully transferred.".encode(FORMAT))

    try:
        sig_filename = client.recv(SIZE).decode(FORMAT)
        sig_data = client.recv(SIZE)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    with open(sig_filename, "wb") as sig_file:
        sig_file.write(sig_data)
    FileCredibility.updateFiles([sig_filename])

    client.send("Receiver signature file has been transferred and authenticated.".encode(FORMAT))

    predicted_size = predict_file_size(filename)
    client.send(f'size={predicted_size}'.encode(FORMAT))
    if predicted_size > MAX_RECEIVE_SIZE:
        print("\nThe file you are encrypting is large. This may take a moment...", end='\r')

    try:
        sym_key = EncMsg.gen_sender_key_file()
    except cryptography.exceptions.InvalidSignature:
        print('\nr.pub is a forgery! The receiver is not who they say they are!\nReturning to SecureDrop menu.\n')
        client.close()
        return

    if type(sym_key) == int and sym_key == -1:
        print("\nCertificate authority declined to sign public key file.\nReturning to SecureDrop menu.\n")
        client.close()
        return

    fn, extension = os.path.splitext(filename)
    if not EncMsg.gen_send_file(sym_key, fn, extension):
        print("Failed to encrypt the file. ERROR_26: file too large")
        client.close()
        return

    client.send("s.pub".encode(FORMAT))
    with open("s.pub", "rb") as sender_public_key_file:
        client.send(sender_public_key_file.read())

    try:
        msg = client.recv(SIZE).decode(FORMAT)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    client.send("s.sig".encode(FORMAT))
    with open("s.sig", "rb") as sender_sig_file:
        client.send(sender_sig_file.read())

    try:
        msg = client.recv(SIZE).decode(FORMAT)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    client.send(filename.encode(FORMAT))
    filesize = get_file_size(fn + '.zok')
    client.send(f'size={filesize}'.encode(FORMAT))

    fenc = fn + ".zok"
    FileCredibility.fullStop(fenc)
    with open(fenc, "rb") as file:
        data = file.read()

    try:
        decision = client.recv(SIZE).decode(FORMAT)
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    if decision == 'n':
        print(f"\n{contact} has declined the large file. Returning to SecureDrop menu.\n")
        client.close()
        return

    print(f'\n{filename} sending...', end='\r')
    client.sendall(data)

    try:
        msg = client.recv(SIZE).decode(FORMAT)
        if ' has been successfully transferred.' in msg:
            print(f'{filename} has been successfully transferred!\n')
        else:
            print(f"\n{msg}\n")
    except:
        print(f"\n{contact} has closed the connection. Returning to SecureDrop menu.\n")
        client.close()
        return

    client.close()
