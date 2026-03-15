"""
Flask-SocketIO Chat Server
--------------------------
A scalable, thread-safe chat server that supports:
  - Room-based messaging with public key caching
  - Hybrid encryption protocol (AES message + RSA-wrapped keys)
  - Heartbeat-based inactivity detection
  - Generic API compatible with any frontend (web, CLI, mobile)
"""

import time
import threading
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_cors import CORS


# =============================================================================
# RoomManager: Thread-safe manager for rooms, users, and public keys
# =============================================================================
class RoomManager:
    """
    Centralizes all room/user/key state behind a single lock,
    preventing race conditions between SocketIO handlers and
    the background inactivity-checker thread.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # { room_name: { username: sid } }
        self._rooms: dict[str, dict[str, str]] = {}
        # { room_name: { username: pem_public_key_str } }
        self._public_keys: dict[str, dict[str, str]] = {}
        # { sid: last_activity_timestamp }
        self._last_activity: dict[str, float] = {}

    # -- Room & User Management -----------------------------------------------

    def add_user(self, username: str, room: str, sid: str) -> bool:
        """Add a user to a room. Returns False if username is already taken."""
        with self._lock:
            if room not in self._rooms:
                self._rooms[room] = {}
            if username in self._rooms[room]:
                return False
            self._rooms[room][username] = sid
            self._last_activity[sid] = time.time()
            return True

    def remove_user(self, username: str, room: str) -> str | None:
        """Remove a user from a room. Returns their sid, or None if not found."""
        with self._lock:
            if room in self._rooms and username in self._rooms[room]:
                sid = self._rooms[room].pop(username)
                self._last_activity.pop(sid, None)
                # Also clean up their cached public key
                if room in self._public_keys:
                    self._public_keys[room].pop(username, None)
                # Remove empty rooms
                if not self._rooms[room]:
                    del self._rooms[room]
                    self._public_keys.pop(room, None)
                return sid
            return None

    def get_user_sid(self, username: str, room: str) -> str | None:
        """Lookup the sid for a user in a room."""
        with self._lock:
            return self._rooms.get(room, {}).get(username)

    def get_room_users(self, room: str) -> dict[str, str]:
        """Return a snapshot of {username: sid} for a room."""
        with self._lock:
            return dict(self._rooms.get(room, {}))

    def is_username_taken(self, username: str, room: str) -> bool:
        with self._lock:
            return username in self._rooms.get(room, {})

    # -- Public Key Caching ----------------------------------------------------

    def cache_public_key(self, username: str, room: str, public_key_pem: str):
        """Store a user's public key for the room so late-joiners can retrieve it."""
        with self._lock:
            if room not in self._public_keys:
                self._public_keys[room] = {}
            self._public_keys[room][username] = public_key_pem

    def get_cached_keys(self, room: str) -> dict[str, str]:
        """Return all cached public keys for a room (excluding the caller)."""
        with self._lock:
            return dict(self._public_keys.get(room, {}))

    # -- Heartbeat / Inactivity ------------------------------------------------

    def record_activity(self, sid: str):
        with self._lock:
            self._last_activity[sid] = time.time()

    def find_inactive_users(self, timeout_seconds: int = 120) -> list[tuple[str, str, str]]:
        """
        Returns a list of (username, room, sid) for users who have been
        inactive for longer than `timeout_seconds`.
        """
        now = time.time()
        inactive = []
        with self._lock:
            stale_sids = [
                sid for sid, ts in self._last_activity.items()
                if now - ts > timeout_seconds
            ]
            for sid in stale_sids:
                for room, users in self._rooms.items():
                    for username, user_sid in list(users.items()):
                        if user_sid == sid:
                            inactive.append((username, room, sid))
        return inactive


# =============================================================================
# Flask App & SocketIO Setup
# =============================================================================
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

room_manager = RoomManager()


# =============================================================================
# HTTP Routes
# =============================================================================
@app.route("/")
def index():
    return "Chat server is running."


# =============================================================================
# SocketIO Event Handlers
# =============================================================================

@socketio.on("join")
def on_join(data):
    """
    Client sends: { username, room }
    Server adds user to the room, broadcasts a join status,
    and sends all cached public keys to the new user.
    """
    username = data["username"]
    room = data["room"]

    if not room_manager.add_user(username, room, request.sid):
        emit("status", {"message": f"Username {username} is already taken in room {room}."})
        disconnect(sid=request.sid)
        return

    join_room(room)
    print(f"[JOIN] {username} → room {room}")

    # Tell everyone in the room (except the new user) that they joined
    emit("status", {"message": f"{username} has joined the room."}, to=room, include_self=False)

    # Send the list of existing users to the new user
    users = room_manager.get_room_users(room)
    user_list = ", ".join(users.keys())
    emit("status", {"message": f"Connected. Users in room: {user_list}"})

    # Send all cached public keys so the new user can encrypt for existing members
    cached_keys = room_manager.get_cached_keys(room)
    for key_username, key_pem in cached_keys.items():
        if key_username != username:
            emit("public_key", {"username": key_username, "public_key": key_pem})


@socketio.on("public_key")
def on_public_key(data):
    """
    Client sends: { username, room, public_key }
    Server caches the key and broadcasts it to the rest of the room.
    """
    username = data["username"]
    room = data["room"]
    public_key_pem = data["public_key"]

    # Cache for future joiners
    room_manager.cache_public_key(username, room, public_key_pem)

    # Broadcast to existing room members so they can encrypt for this user
    emit("public_key", {"username": username, "public_key": public_key_pem},
         room=room, include_self=False)


@socketio.on("message")
def on_message(data):
    """
    Hybrid Encryption Message Handler
    ----------------------------------
    Client sends: {
        sender:    "@alice:",
        room:      "room1",
        payload:   "<base64 AES-encrypted message>",
        iv:        "<base64 AES initialization vector>",
        keys: {
            "@bob:":    "<base64 RSA-encrypted AES key for bob>",
            "@charlie:":"<base64 RSA-encrypted AES key for charlie>"
        }
    }

    The server routes each recipient their specific encrypted AES key
    along with the shared AES-encrypted payload. The server never sees
    the plaintext message or the plaintext AES key.
    """
    sender = data["sender"]
    room = data["room"]
    payload = data["payload"]          # AES-encrypted message (shared)
    iv = data["iv"]                    # AES initialization vector (shared)
    encrypted_keys = data["keys"]      # { recipient_username: rsa_encrypted_aes_key }

    for recipient, encrypted_aes_key in encrypted_keys.items():
        recipient_sid = room_manager.get_user_sid(recipient, room)
        if recipient_sid:
            emit("message", {
                "sender": sender,
                "payload": payload,
                "iv": iv,
                "key": encrypted_aes_key,
            }, to=recipient_sid)


@socketio.on("private_message")
def on_private_message(data):
    """
    Same hybrid format as 'message', but targeted at a single recipient.
    Client sends: { sender, recipient, room, payload, iv, key }
    """
    sender = data["sender"]
    recipient = data["recipient"]
    room = data["room"]

    recipient_sid = room_manager.get_user_sid(recipient, room)
    if recipient_sid:
        emit("message", {
            "sender": sender,
            "payload": data["payload"],
            "iv": data["iv"],
            "key": data["key"],
        }, to=recipient_sid)


@socketio.on("leave_room")
def on_leave(data):
    username = data["username"]
    room = data["room"]

    sid = room_manager.remove_user(username, room)
    if sid:
        leave_room(room, sid=sid)
        emit("status", {"message": f"{username} has left the room."}, to=room)
        disconnect(sid=sid)
        print(f"[LEAVE] {username} ← room {room}")


@socketio.on("ping_server")
def on_ping(data):
    """Heartbeat: client pings periodically to signal it is still alive."""
    room_manager.record_activity(request.sid)


# =============================================================================
# Background: Inactivity Checker
# =============================================================================
def check_inactivity():
    """Runs in a daemon thread. Removes users who haven't pinged in 2 minutes."""
    while True:
        inactive = room_manager.find_inactive_users(timeout_seconds=120)
        for username, room, sid in inactive:
            room_manager.remove_user(username, room)
            print(f"[TIMEOUT] {username} removed from {room} (inactive)")
        time.sleep(10)


# =============================================================================
# Entry Point
# =============================================================================
if __name__ == "__main__":
    heartbeat = threading.Thread(target=check_inactivity, daemon=True)
    heartbeat.start()
    socketio.run(app, host="0.0.0.0", port=12345)
