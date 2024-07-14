import json
from flask import Flask,request
from flask_socketio import SocketIO, emit, join_room, leave_room , disconnect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*",logger=True, engineio_logger=True)


# Store user public keys by room
rooms = {}  # {roomName: {username: public_key}}
public_keys = {}

def add_user_to_room(username, room_name,sid):
    if room_name not in rooms:
        rooms[room_name] = {}
    rooms[room_name][username] = sid;

def checkUserNameAvalibility(username, room_name):
    if room_name in rooms and username in rooms[room_name]:
        return False
    return True

@app.route('/')
def index():
    return "Chat server is running."


@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    if checkUserNameAvalibility(username,room) == False:
        emit('status', {'message': f"Username {username} already exists in the room {room}."})
        disconnect()
        
    add_user_to_room(username, room,request.sid)
    join_room(room)
    print(f"{username} has joined the room {room}.")
    broadcast_to_room(username,room,f"{username} has joined the room.")




@socketio.on('public_key')
def on_public_key(data):
    username = data['username']
    room = data['room']
    public_key = data['public_key']
    public_keys[username] = public_key
    emit('public_key', {"username":username,"public_key":public_key}, room=room,include_self=False)




def broadcast_to_room(sender, room, message):
    if room in rooms and sender in rooms[room]:
        emit('status', {'message': f"{message}"}, to=room, include_self=False)
    

@socketio.on('private_message')
def on_private_message(data):
    sender = data['sender']
    recipient = data['recipient']
    room = data['room']
    message = data['message']
    send_private_message(sender, recipient, room, message)


def send_private_message(sender, recipient, room, message):
    if room in rooms and recipient in rooms[room] and public_keys[recipient] is not None:
        emit('private_message', {'message': message,"sender":sender}, to=rooms[room][recipient])


@socketio.on('leave')
def on_disconnect(data):
    username = data['username']
    room = data['room']
    if room in rooms and username in rooms[room]:
        del rooms[room][username]
        public_keys.pop(username)
        emit('status', {'message': f"{username} has left the room."}, room=room, broadcast=True)

            

def is_user_disconnected(username):
    # Placeholder function for checking if a user is disconnected
    # You might need to track connected users separately
    return False

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=12345)