import json
import base64
import time
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from flask_cors import CORS
from threading import Thread

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*",)

# Store user public keys by room
rooms = {}  # {roomName: {username: sid}}
public_keys = {}
last_activity = {}  # {sid: timestamp}


def add_user_to_room(username, room_name, sid):
    if room_name not in rooms:
        rooms[room_name] = {}
    rooms[room_name][username] = sid


def check_username_availability(username, room_name):
    return room_name in rooms and username in rooms[room_name]


@app.route('/')
def index():
    return "Chat server is running."


@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    if check_username_availability(username, room):
        emit('status', {'message': f"Username {username} already exists in the room {room}."})
        disconnect(sid=request.sid)
        return
    
    add_user_to_room(username, room, request.sid)
    join_room(room)
    print(f"{username} has joined the room {room}.")
    broadcast_to_room(username, room,f"{username} has joined the room {room}.")


@socketio.on('public_key')
def on_public_key(data):
    username = data['username']
    room = data['room']
    public_key = data['public_key']
    emit('public_key', {"username": username, "public_key": public_key}, room=room, include_self=False)


def broadcast_to_room(sender, room,message):
    join_Message = ""
    for username,sid in rooms[room].items():
        join_Message += f"{username} has joined the room {room}.\n"
    join_Message = join_Message.removesuffix("\n")
    if room in rooms and sender in rooms[room]:
        emit('status', {'message': message}, to=room, include_self=False)
    
    emit('status', {'message': join_Message}, room=rooms[room][sender])


@socketio.on('private_message')
def on_private_message(data):
    sender = data['sender']
    recipient = data['recipient']
    room = data['room']
    message = data['message']
    send_private_message(sender, recipient, room, message)


def send_private_message(sender, recipient, room, message):
    if room in rooms and recipient in rooms[room] :
        emit('private_message', {'message': message, "sender": sender}, to=rooms[room][recipient])


@socketio.on('leave_room')
def on_leave(data):
    username = data['username']
    room = data['room']
    if room in rooms and username in rooms[room]:
        s = rooms[room][username]
        del rooms[room][username]
        leave_room(room,sid=s)
        emit('status', {'message': f"{username} has left the room."}, to=room)
        disconnect(sid=s)
        print(f"{username} has left the room {room}.")


@socketio.on('ping_server')
def on_ping(data):
    username = data['username']
    print(f"Received ping from ${username}.")
    last_activity[request.sid] = time.time()

def check_inactivity():
    while True:
        now = time.time()
        to_remove = []
        for sid, last_time in last_activity.items():
            if now - last_time > 120:  # 2 minutes
                to_remove.append(sid)
        
        for sid in to_remove:
            for room, users in rooms.items():
                for username, user_sid in users.items():
                    if user_sid == sid:
                        del rooms[room][username]
                        #emit('status', {'message': f"{username} has been removed due to inactivity."}, to=room)
                        #disconnect(sid=sid)
                        del last_activity[sid]
                        print(f"{username} has been removed due to inactivity.")
                        break
            last_activity.pop(sid, None)
        
        time.sleep(10)



if __name__ == '__main__':
    heartBeat = Thread(target=check_inactivity)
    heartBeat.daemon = True
    heartBeat.start()
    socketio.run(app, host='0.0.0.0', port=12345)
