import socketio
import base64
import socket
import sys
import threading
import time
import colorama
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import requests

import curses
from curses.textpad import Textbox, rectangle



green_on_black = None
green_on_blue = None
receiver_win = None
check = False
log_file = "log.txt"
receiver_max_row = None
sender_max_row = None

finished = False
username = ""
keys = {}  # Dictionary to store public keys of other users
public_key = None
private_key = None
room_id = None



def generate_private_public_key():
    """
    Generate a private key and its corresponding public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key




# Create a Socket.IO client
sio = socketio.Client()

# Event handler for connection
@sio.event
def connect():
    pass

# Event handler for disconnection
@sio.event
def disconnect():
    print("Disconnected from the server")

# Event handler for receiving messages




log_file_lock = threading.Lock()

def append_to_log_file(text):
    """
    Append the given text to the log file.
    """
    global log_file

    # Acquire the lock before entering the critical section
    with log_file_lock:
        text = text.strip()
        with open(log_file, "a") as file:
            file.write(text + "\n")
        show_last_n_lines()  # Move show_last_n_lines inside the lock block to ensure thread safety


def show_last_n_lines():
    """
    Display the last N lines from the log file in the receiver window.
    """
    global receiver_win, log_file, receiver_max_row
    lines = []
    with open(log_file, "r") as file:
        lines = file.readlines()
    file.close()
    last_six_lines = lines[-receiver_max_row+2:]
    receiver_win.move(1, 0)
    for line in last_six_lines:
        receiver_win.addstr(f" {line}")
        receiver_win.refresh()



def encrypt_message(message):
    """
    Encrypt and send a message to all recipients.
    """
    global keys
    message_val = message.encode()
    for receiver_username, receiver_pub_key in keys.items():
        ciphertext = receiver_pub_key.encrypt(
            message_val,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        sio.emit('private_message', {"sender": username,"recipient":receiver_username,"room": room_id, "message": ciphertext_b64})



def decrypt_message(ciphertext):
    """
    Decrypt a ciphertext using the private key.
    """
    global private_key
    ciphertext = base64.b64decode(ciphertext)
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()



def print_simple_message(message, sender_username):
    """
    Print a simple message in the format "sender_username: message".
    """
    message = f"{sender_username}:{message}"
    append_to_log_file(message)



@sio.on('private_message')
def on_private_message(data):
    message = data['message']
    sender_username = data['sender']
    message = decrypt_message(message)
    print_simple_message(message, sender_username)


@sio.on('status')
def on_status(data):
    message = data['message']
    append_to_log_file(message)




def store_public_key(sender_username,sender_public_key: str):
    """
    Store the public key of the sender in the keys dictionary.
    Return True if the key already exists in the dictionary, False otherwise.
    """
    global keys
    
    sender_public_key = sender_public_key.encode()
    sender_public_key = serialization.load_pem_public_key(sender_public_key)
    if sender_username in keys:
        return True
    keys[sender_username] = sender_public_key
    return False


def send_public_key():
    """
    Send the local public key to the server.
    """
    global public_key, username, room_id
    local_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    sio.emit('public_key',{"username":username,"room": room_id,"public_key": local_public_key})





@sio.on('public_key')
def on_public_key(data):
    global username, public_key, room_id
    sender_username = data['username']
    sender_public_key = data['public_key']
    if store_public_key(sender_username,sender_public_key):
        return 
    else :
        append_to_log_file(f"{sender_username} has joined the room.")
        send_public_key()
    




def receive_messages(stdscr):
    """
    Receive and process messages from the server.
    """
    global finished, receiver_win

    # Create the receiver window
    receiver_win = stdscr.subwin(receiver_max_row, curses.COLS, 0, 0)
    receiver_win.bkgd(' ', green_on_black)  # Set background color
    receiver_win.clear()
    receiver_win.move(0, 4)
    receiver_win.addstr(f"Messages", curses.A_BOLD)
    receiver_win.refresh()


def send_messages(stdscr):
    """
    Send messages to the server.
    """
    global finished, green_on_black

    # Create the sender window
    sender_win = curses.newwin(sender_max_row, curses.COLS, curses.LINES-sender_max_row, 0)
    sender_win.bkgd(' ', green_on_black)  # Set background color
    sender_win.clear()
    sender_win.addstr("\n Write message here", curses.A_BOLD)
    sender_win.refresh()

    # Draw a rectangle inside the sender window
    rectangle(sender_win, 0, 0, sender_max_row-2, curses.COLS-1)
    sender_win.refresh()

    # Create a subwindow within the rectangle for input
    sender_win_sub = curses.newwin(sender_max_row-4, curses.COLS-2, curses.LINES-sender_max_row+2, 1)
    sender_win_sub.bkgd(' ', green_on_black)
    box = Textbox(sender_win_sub,insert_mode=True)
    sender_win_sub.move(0, 0)
    sender_win_sub.refresh()

    while not finished:
        box.edit()
        message = box.gather().strip()
        if message.strip() == "exit()":
            finished = True
            sio.emit('leave_room',{"username":username,"room":room_id})
            sio.disconnect()
            break
        encrypt_message( message)
        append_to_log_file(message)
        sender_win_sub.clear()
        sender_win_sub.refresh()

        


def connect_to_server(stdscr):
    """
    Connect to the server and start the chat.
    """
    global username, public_key, room_id
    try:
        sio.connect('http://100.20.92.101:12345')
        #print("Connected to the server.")
        receive_messages(stdscr)

        #send_thread.join()
        #send_messages(stdscr)
        # Create and send the initial join room message
        username = f"@{username}:"
        initial_message = {
            "username":username,
            "room":room_id
        }
        sio.emit('join', initial_message)

        
        send_public_key()

        # Create and send the public key message
        
        send_thread = threading.Thread(target=send_messages, args=(stdscr,))
        send_thread.start()
        send_thread.join()
        
        
    except Exception as e:
        print("Failed to connect to the server.")
    finally:
        sys.exit()


def main(stdscr):
    """
    Main function to initialize the curses window and start the chat.
    """
    global green_on_black, green_on_blue, receiver_max_row, sender_max_row
    curses.curs_set(0)  

    with open(log_file, 'w') as file:
        file.close()

    curses.start_color()  # Enable color support
    curses.use_default_colors()  # Use default terminal colors
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Set color pair
    green_on_black = curses.color_pair(1)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_CYAN)
    green_on_blue = curses.color_pair(2)
    stdscr.clear()
    stdscr.refresh()

    if curses.LINES < 20:
        return

    receiver_max_row = int(curses.LINES*(2/3))
    sender_max_row = int(curses.LINES*(1/3))
    if receiver_max_row + sender_max_row != curses.LINES:
        receiver_max_row += 1

    connect_to_server(stdscr)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 scriptName.py <room_id> <username>")
    else:
        room_id = sys.argv[1]
        username = sys.argv[2]
        private_key, public_key = generate_private_public_key()

        curses.wrapper(main)




