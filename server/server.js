/**
 * Chat Server (Node.js + Socket.IO)
 * -----------------------------------
 * A high-concurrency WebSocket server that acts as a stateless message
 * router for E2EE (End-to-End Encrypted) chat. The server never sees
 * plaintext messages — it only forwards encrypted blobs between clients.
 *
 * Responsibilities:
 *   - Room & user management (in-memory)
 *   - Public key caching (so late-joiners get existing keys instantly)
 *   - Routing hybrid-encrypted messages (AES payload + RSA-wrapped keys)
 *   - Heartbeat-based inactivity cleanup
 */

const http = require("http");
const { Server } = require("socket.io");
const winston = require("winston");

// Configure structured logging to both terminal and a text file
const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: "server.log" })
    ],
});

// =============================================================================
// Configuration
// =============================================================================
const PORT = process.env.PORT || 12345;
const INACTIVITY_TIMEOUT_MS = 2 * 60 * 1000; // 2 minutes
const INACTIVITY_CHECK_INTERVAL_MS = 10 * 1000; // check every 10 seconds

// =============================================================================
// In-Memory Store
// =============================================================================

/**
 * rooms: Map<roomName, Map<username, socketId>>
 * Tracks which users are in which rooms and their socket IDs.
 */
const rooms = new Map();

/**
 * publicKeys: Map<roomName, Map<username, pemString>>
 * Caches each user's public key per room so new joiners receive
 * all existing keys without triggering a broadcast storm.
 */
const publicKeys = new Map();

/**
 * lastActivity: Map<socketId, timestamp>
 * Records the last heartbeat ping from each connected socket.
 */
const lastActivity = new Map();

// =============================================================================
// Room Manager Helpers
// =============================================================================

function addUser(username, room, socketId) {
    if (!rooms.has(room)) {
        rooms.set(room, new Map());
        logger.info(`[ROOM CREATED] Room '${room}' was created by ${username}.`);
    } else {
        logger.info(`[ROOM JOIN] ${username} is attempting to join existing room '${room}'.`);
    }
    const roomUsers = rooms.get(room);
    if (roomUsers.has(username)) return false; // username taken
    roomUsers.set(username, socketId);
    lastActivity.set(socketId, Date.now());
    return true;
}

function removeUser(username, room) {
    const roomUsers = rooms.get(room);
    if (!roomUsers || !roomUsers.has(username)) return null;

    const socketId = roomUsers.get(username);
    roomUsers.delete(username);
    lastActivity.delete(socketId);

    // Clean up cached public key
    const roomKeys = publicKeys.get(room);
    if (roomKeys) roomKeys.delete(username);

    // Remove empty rooms to prevent memory leaks
    if (roomUsers.size === 0) {
        rooms.delete(room);
        publicKeys.delete(room);
    }

    return socketId;
}

function getUserSid(username, room) {
    const roomUsers = rooms.get(room);
    return roomUsers ? roomUsers.get(username) : undefined;
}

function getRoomUsers(room) {
    return rooms.get(room) || new Map();
}

function cachePublicKey(username, room, pem) {
    if (!publicKeys.has(room)) publicKeys.set(room, new Map());
    publicKeys.get(room).set(username, pem);
}

function getCachedKeys(room) {
    return publicKeys.get(room) || new Map();
}

/**
 * Find the username and room for a given socket ID.
 * Used during disconnect to clean up user state.
 */
function findUserBySocketId(socketId) {
    for (const [room, users] of rooms) {
        for (const [username, sid] of users) {
            if (sid === socketId) return { username, room };
        }
    }
    return null;
}

// =============================================================================
// HTTP + Socket.IO Server
// =============================================================================

const httpServer = http.createServer((req, res) => {
    // Simple health-check endpoint
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("Chat server is running.");
});

const io = new Server(httpServer, {
    cors: {
        origin: "*", // Allow any frontend origin (web, CLI, mobile)
        methods: ["GET", "POST"],
    },
});

// =============================================================================
// Socket.IO Event Handlers
// =============================================================================

io.on("connection", (socket) => {
    // -- Join a Room ------------------------------------------------------------
    socket.on("join", (data) => {
        const { username, room } = data;

        if (!addUser(username, room, socket.id)) {
            socket.emit("status", {
                message: `Username ${username} is already taken in room ${room}.`,
            });
            socket.disconnect(true);
            return;
        }

        socket.join(room);
        logger.info(`[JOIN SUCCESS] ${username} successfully joined room '${room}'.`);

        // Notify existing members
        socket.to(room).emit("status", {
            message: `${username} has joined the room.`,
        });

        // Send user list to the new member
        const users = [...getRoomUsers(room).keys()].join(", ");
        socket.emit("status", {
            message: `Connected. Users in room: ${users}`,
        });

        // Send all cached public keys so the new user can encrypt for existing members
        const cached = getCachedKeys(room);
        for (const [keyUsername, pem] of cached) {
            if (keyUsername !== username) {
                socket.emit("public_key", { username: keyUsername, public_key: pem });
            }
        }
    });

    // -- Public Key Exchange ----------------------------------------------------
    socket.on("public_key", (data) => {
        const { username, room, public_key } = data;
        logger.info(`[KEY RECEIVED] Received public key from ${username} in room '${room}'.`);

        // Cache for future joiners
        cachePublicKey(username, room, public_key);

        // Broadcast to existing room members (not the sender)
        socket.to(room).emit("public_key", { username, public_key });
        logger.info(`[KEY BROADCAST] Broadcasted ${username}'s public key to other members of room '${room}'.`);
    });

    // -- Hybrid Encrypted Room Message ------------------------------------------
    /**
     * Expected payload from client:
     * {
     *   sender:  "@alice:",
     *   room:    "room1",
     *   payload: "<base64 AES-encrypted message>",
     *   iv:      "<base64 AES initialization vector>",
     *   keys: {
     *     "@bob:":    "<base64 RSA-encrypted AES key for bob>",
     *     "@charlie:":"<base64 RSA-encrypted AES key for charlie>"
     *   }
     * }
     *
     * The server routes each recipient their specific RSA-wrapped AES key
     * alongside the shared AES payload. It never sees plaintext.
     */
    socket.on("message", (data) => {
        const { sender, room, payload, iv, keys } = data;

        logger.info(`[MESSAGE] Routing encrypted room message from ${sender} to ${Object.keys(keys).length} recipients in room '${room}'.`);

        for (const [recipient, encryptedAesKey] of Object.entries(keys)) {
            const recipientSid = getUserSid(recipient, room);
            if (recipientSid) {
                logger.info(`[MESSAGE DELIVERED] Routed message from ${sender} specifically to ${recipient}.`);
                io.to(recipientSid).emit("message", {
                    sender,
                    payload,
                    iv,
                    key: encryptedAesKey,
                });
            } else {
                logger.info(`[MESSAGE FAILED] Recipient ${recipient} not found in room '${room}'. `);
            }
        }
    });

    // -- Hybrid Encrypted Private Message ---------------------------------------
    socket.on("private_message", (data) => {
        const { sender, recipient, room, payload, iv, key } = data;

        const recipientSid = getUserSid(recipient, room);
        if (recipientSid) {
            io.to(recipientSid).emit("message", { sender, payload, iv, key });
        }
    });

    // -- Leave Room -------------------------------------------------------------
    socket.on("leave_room", (data) => {
        const { username, room } = data;

        const sid = removeUser(username, room);
        if (sid) {
            socket.to(room).emit("status", {
                message: `${username} has left the room.`,
            });
            socket.leave(room);
            logger.info(`[LEAVE] ${username} ← room ${room}`);
            socket.disconnect(true);
        }
    });

    // -- Heartbeat Ping ---------------------------------------------------------
    socket.on("ping_server", () => {
        lastActivity.set(socket.id, Date.now());
    });

    // -- Unexpected Disconnect (browser close, network drop) --------------------
    socket.on("disconnect", () => {
        const user = findUserBySocketId(socket.id);
        if (user) {
            removeUser(user.username, user.room);
            io.to(user.room).emit("status", {
                message: `${user.username} has disconnected.`,
            });
            logger.info(`[DISCONNECT] ${user.username} ← room ${user.room}`);
        }
    });
});

// =============================================================================
// Background: Inactivity Checker
// =============================================================================
setInterval(() => {
    const now = Date.now();

    for (const [socketId, timestamp] of lastActivity) {
        if (now - timestamp > INACTIVITY_TIMEOUT_MS) {
            const user = findUserBySocketId(socketId);
            if (user) {
                removeUser(user.username, user.room);
                io.to(user.room).emit("status", {
                    message: `${user.username} was removed due to inactivity.`,
                });
                // Force-disconnect the stale socket
                const staleSocket = io.sockets.sockets.get(socketId);
                if (staleSocket) staleSocket.disconnect(true);
                logger.info(`[TIMEOUT] ${user.username} removed from ${user.room} (inactive)`);
            } else {
                // Orphaned entry — clean up
                lastActivity.delete(socketId);
            }
        }
    }
}, INACTIVITY_CHECK_INTERVAL_MS);

// =============================================================================
// Start Server
// =============================================================================
httpServer.listen(PORT, "0.0.0.0", () => {
    logger.info(`Chat server running on http://0.0.0.0:${PORT}`);
});
