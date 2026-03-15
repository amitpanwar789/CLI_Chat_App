"""
Textual CLI Chat Client
-----------------------
A modern, async terminal UI for the E2EE Chat app using the Textual framework.
Features:
  - Scrollable message log
  - Floating input bar
  - Hybrid encryption (AES + RSA)
  - Async Socket.IO connection
"""

import asyncio
import sys
import base64
import os
import socketio

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Header, Footer, Input, RichLog, Static
from textual.binding import Binding

# =============================================================================
# Crypto Utilities (Hybrid Encryption: Same as before)
# =============================================================================

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def aes_encrypt(plaintext: bytes):
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return aes_key, iv, ciphertext

def aes_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(aes_key).decrypt(iv, ciphertext, None)

def rsa_encrypt_key(aes_key: bytes, recipient_public_key) -> bytes:
    return recipient_public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt_key(encrypted_aes_key: bytes, private_key) -> bytes:
    return private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def serialize_public_key(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def deserialize_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode())


# =============================================================================
# Textual App
# =============================================================================

class ChatApp(App):
    """The main Textual application for the Chat UI."""

    CSS = """
    #main-container {
        height: 100%;
    }
    #chat-log {
        height: 1fr;
        border: solid green;
        background: $surface;
        padding: 0 1;
    }
    #message-input {
        dock: bottom;
        margin: 1 0;
        border: solid lime;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", show=True, priority=True),
    ]

    def __init__(self, room_id: str, username: str, server_url: str):
        super().__init__()
        self.room_id = room_id
        self.username = f"@{username}:"
        self.server_url = server_url
        
        # UI Widgets
        self.log_widget = RichLog(id="chat-log", markup=True, highlight=True, wrap=True)
        self.input_widget = Input(placeholder="Type a message and press Enter...", id="message-input")
        
        # Crypto State
        self.private_key, self.public_key = generate_rsa_keypair()
        self.peer_keys: dict = {} # {username: RSAPublicKey}
        
        # Networking State
        self.sio = socketio.AsyncClient()
        self._ping_task = None

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header(show_clock=True)
        yield Vertical(
            self.log_widget,
            self.input_widget,
            id="main-container"
        )
        yield Footer()

    async def on_mount(self) -> None:
        """Called when the app starts. Focus input and connect to server."""
        self.input_widget.focus()
        self.title = f"Room: {self.room_id} | User: {self.username.strip(':')}"
        
        # Log to file (append only)
        self.log_file = f"log_{self.username.strip('@:')}.txt"
        open(self.log_file, 'a').close() # touch file
        
        self.print_log(f"[bold green]Starting connection to {self.server_url}...[/]")
        self.setup_socket_events()
        
        # Connect asynchronously without blocking UI
        asyncio.create_task(self.connect_to_server())

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        """Called when the user presses Enter in the Input widget."""
        text = message.value.strip()
        if not text:
            return
            
        if text.lower() == "exit()":
            self.exit()
            return
            
        # Clear input box immediately
        self.input_widget.value = ""
        
        # Check for private message command: /DM @username: message content
        if text.lower().startswith("/dm "):
            parts = text.split(" ", 2)
            if len(parts) >= 3:
                raw_recipient = parts[1]
                private_text = parts[2]
                
                # Auto-format the username to strictly match "@username:" for ease of use
                clean_name = raw_recipient.strip(":,@")
                target_key = f"@{clean_name}:"
                
                success, real_target_key, error_msg = await self.send_private_message(private_text, target_key)
                if success:
                    self.print_log(f"[bold blue](DM to {real_target_key})[/] {private_text}")
                else:
                    self.print_log(f"[bold red]{error_msg}[/]")
                return
            else:
                self.print_log("[bold red]Invalid format. Use: /DM @username: message[/]")
                return

        # Send regular room message
        await self.send_room_message(text)
        self.print_log(f"[bold blue]{self.username}[/] {text}")

    async def on_unmount(self) -> None:
        """Cleanup before exiting."""
        if self._ping_task:
            self._ping_task.cancel()
        try:
            await self.sio.emit("leave_room", {"username": self.username, "room": self.room_id})
        except Exception:
            pass
        await self.sio.disconnect()

    def print_log(self, text: str) -> None:
        """Write to the Textual RichLog widget and the log file."""
        self.log_widget.write(text)
        try:
            # We strip rich markup for the raw text log file
            from rich.text import Text
            raw_text = Text.from_markup(text).plain
            with open(self.log_file, "a") as f:
                f.write(raw_text + "\n")
        except Exception as e:
            pass

    # -- Networking & Crypto --------------------------------------------------

    def setup_socket_events(self):
        @self.sio.event
        async def connect():
            pass

        @self.sio.event
        async def disconnect():
            self.print_log("[bold red]Disconnected from server.[/]")

        @self.sio.on("public_key")
        async def on_public_key(data):
            sender = data["username"]
            pem = data["public_key"]
            if sender not in self.peer_keys:
                self.peer_keys[sender] = deserialize_public_key(pem)
                # Inform new user of our key
                await self.sio.emit("public_key", {
                    "username": self.username,
                    "room": self.room_id,
                    "public_key": serialize_public_key(self.public_key)
                })

        @self.sio.on("status")
        async def on_status(data):
            self.print_log(f"[italic yellow]{data['message']}[/]")

        @self.sio.on("message")
        async def on_message(data):
            sender = data["sender"]
            try:
                encrypted_aes_key = base64.b64decode(data["key"])
                iv = base64.b64decode(data["iv"])
                payload = base64.b64decode(data["payload"])

                aes_key = rsa_decrypt_key(encrypted_aes_key, self.private_key)
                plaintext = aes_decrypt(aes_key, iv, payload).decode()
                
                # Highlight other users' messages
                self.print_log(f"[bold magenta]{sender}[/] {plaintext}")
            except Exception as e:
                self.print_log(f"[bold magenta]{sender}[/] [red][Decryption Failed][/]")

    async def connect_to_server(self):
        try:
            await self.sio.connect(self.server_url)
            await self.sio.emit("join", {"username": self.username, "room": self.room_id})
            
            # Send our public key
            await self.sio.emit("public_key", {
                "username": self.username,
                "room": self.room_id,
                "public_key": serialize_public_key(self.public_key),
            })
            
            # Start keep-alive ping loop
            self._ping_task = asyncio.create_task(self._ping_loop())
            
        except Exception as e:
            self.print_log(f"[bold red]Connection failed:[/] {e}")

    async def _ping_loop(self):
        while True:
            await asyncio.sleep(10)
            if self.sio.connected:
                await self.sio.emit("ping_server", {"username": self.username, "room": self.room_id})

    async def send_room_message(self, message: str):
        if not self.peer_keys:
            self.print_log("[dim yellow]No peers to send to — waiting for others to join.[/]")
            return

        aes_key, iv, ciphertext = aes_encrypt(message.encode())
        encrypted_keys = {}
        
        for peer_username, peer_pub_key in self.peer_keys.items():
            wrapped = rsa_encrypt_key(aes_key, peer_pub_key)
            encrypted_keys[peer_username] = base64.b64encode(wrapped).decode()

        await self.sio.emit("message", {
            "sender": self.username,
            "room": self.room_id,
            "payload": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "keys": encrypted_keys,
        })

    async def send_private_message(self, message: str, recipient: str):
        # Case-insensitive lookup for the recipient
        real_recipient = None
        for key in self.peer_keys.keys():
            if key.lower() == recipient.lower():
                real_recipient = key
                break
                
        if not real_recipient:
            return False, None, f"User {recipient} not found or no public key available."

        # Hybrid encrypt for single recipient
        aes_key, iv, ciphertext = aes_encrypt(message.encode())
        peer_pub_key = self.peer_keys[real_recipient]
        wrapped = rsa_encrypt_key(aes_key, peer_pub_key)
        encrypted_key = base64.b64encode(wrapped).decode()

        await self.sio.emit("private_message", {
            "sender": self.username,
            "recipient": real_recipient,
            "room": self.room_id,
            "payload": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "key": encrypted_key,
        })
        return True, real_recipient, ""


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 cli_client.py <room_id> <username> [server_url]")
        print("Example: python3 cli_client.py Room1 Alice https://my-backend.onrender.com")
        sys.exit(1)

    room_id = sys.argv[1]
    username = sys.argv[2]
    server_url = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:12345"

    app = ChatApp(room_id, username, server_url)
    app.run()
