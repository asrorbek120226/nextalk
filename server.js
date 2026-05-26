const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(__dirname));

// Channels mapping - rooms metadata
const rooms = {
  'general': {
    id: 'general',
    name: 'General',
    emoji: '💬',
    lastMsg: null
  },
  'lounge': {
    id: 'lounge',
    name: 'Lounge',
    emoji: '☕',
    lastMsg: null
  },
  'gaming': {
    id: 'gaming',
    name: 'Gaming',
    emoji: '🎮',
    lastMsg: null
  }
};

const roomEmojis = ['🚀', '💡', '🎵', '🍕', '🏆', '🎨', '🍿', '🌍', '⚡', '🔐'];

// Initialize room previews from database history on startup
async function initRoomPreviews() {
  for (const roomId of Object.keys(rooms)) {
    const messages = await db.getMessages(roomId);
    if (messages.length > 0) {
      rooms[roomId].lastMsg = messages[messages.length - 1];
    }
  }
}

// Get room list overview without full message history (for sidebar)
function getRoomList() {
  return Object.values(rooms).map(r => ({
    id: r.id,
    name: r.name,
    emoji: r.emoji,
    lastMsg: r.lastMsg
  }));
}

// Function to update the online count in a specific room
function updateOnlineCount(roomId) {
  const roomClients = io.sockets.adapter.rooms.get(roomId);
  const count = roomClients ? roomClients.size : 0;
  io.to(roomId).emit('online-count', count);
}

io.on('connection', (socket) => {
  socket.userName = '';
  socket.currentRoom = null;

  // Handle registration
  socket.on('register', async ({ name, email, password }) => {
    try {
      const cleanName = name ? name.trim() : '';
      const cleanEmail = email ? email.trim().toLowerCase() : '';

      if (!cleanName || !cleanEmail || !password) {
        socket.emit('auth-error', 'Please fill in all fields!');
        return;
      }

      if (cleanName.length > 30) {
        socket.emit('auth-error', 'Name cannot exceed 30 characters!');
        return;
      }

      if (password.length < 6) {
        socket.emit('auth-error', 'Password must be at least 6 characters!');
        return;
      }

      // Check if user exists
      const existingUser = await db.getUserByEmail(cleanEmail);
      if (existingUser) {
        socket.emit('auth-error', 'Email is already registered!');
        return;
      }

      // Hash password and add user
      const passwordHash = await bcrypt.hash(password, 10);
      const user = await db.addUser(cleanName, cleanEmail, passwordHash);

      socket.userName = user.name;
      socket.emit('register-success', { name: user.name, email: user.email });
      
      // Send the initial room list now that they are authenticated
      socket.emit('room-list', getRoomList());
    } catch (err) {
      console.error('Registration error:', err);
      socket.emit('auth-error', 'An error occurred during registration.');
    }
  });

  // Handle login
  socket.on('login', async ({ email, password }) => {
    try {
      const cleanEmail = email ? email.trim().toLowerCase() : '';

      if (!cleanEmail || !password) {
        socket.emit('auth-error', 'Please enter email and password!');
        return;
      }

      // Fetch user from DB
      const user = await db.getUserByEmail(cleanEmail);
      if (!user) {
        socket.emit('auth-error', 'Incorrect email or password!');
        return;
      }

      // Compare passwords
      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        socket.emit('auth-error', 'Incorrect email or password!');
        return;
      }

      socket.userName = user.name;
      socket.emit('login-success', { name: user.name, email: user.email });
      
      // Send the initial room list now that they are authenticated
      socket.emit('room-list', getRoomList());
    } catch (err) {
      console.error('Login error:', err);
      socket.emit('auth-error', 'An error occurred during login.');
    }
  });

  // Handle room joining
  socket.on('join-room', async ({ roomId, userName }) => {
    // Basic verification - must be authenticated (have userName set)
    if (!socket.userName) {
      socket.emit('error-msg', 'Please authenticate first!');
      return;
    }

    const room = rooms[roomId];
    if (!room) {
      socket.emit('error-msg', 'Room not found!');
      return;
    }

    // Leave previous room if any
    if (socket.currentRoom && socket.currentRoom !== roomId) {
      const oldRoomId = socket.currentRoom;
      socket.leave(oldRoomId);
      socket.to(oldRoomId).emit('user-left', { name: socket.userName });
      updateOnlineCount(oldRoomId);
    }

    // Join new room
    socket.join(roomId);
    socket.currentRoom = roomId;

    // Load message history from DB
    const history = await db.getMessages(roomId);
    socket.emit('history', history);

    // Broadcast user joined
    socket.to(roomId).emit('user-joined', { name: socket.userName });
    
    updateOnlineCount(roomId);
  });

  // Handle room creation
  socket.on('create-room', ({ name }) => {
    if (!socket.userName) return;

    const cleanName = name.trim();
    if (!cleanName) return;

    const id = cleanName
      .toLowerCase()
      .replace(/\s+/g, '-')
      .replace(/[^a-z0-9-]/g, '');

    if (!id) {
      socket.emit('error-msg', 'Invalid channel name!');
      return;
    }

    if (rooms[id]) {
      socket.emit('error-msg', 'Channel already exists!');
      return;
    }

    const emoji = roomEmojis[Math.floor(Math.random() * roomEmojis.length)];
    
    rooms[id] = {
      id,
      name: cleanName,
      emoji,
      lastMsg: null
    };

    io.emit('new-room', {
      id,
      name: cleanName,
      emoji,
      lastMsg: null
    });
  });

  // Handle message sending
  socket.on('message', async ({ text }) => {
    const roomId = socket.currentRoom;
    if (!roomId || !rooms[roomId] || !socket.userName) return;

    const cleanText = text.trim();
    if (!cleanText) return;

    const message = {
      room: roomId,
      name: socket.userName,
      text: cleanText,
      time: Date.now()
    };

    // Save message to persistent database
    await db.addMessage(roomId, message);
    rooms[roomId].lastMsg = message;

    // Emit message to everyone in the room
    io.to(roomId).emit('message', message);

    // Refresh sidebars with latest message previews
    io.emit('room-list', getRoomList());
  });

  // Handle typing status
  socket.on('typing', (isTyping) => {
    const roomId = socket.currentRoom;
    if (!roomId || !socket.userName) return;

    socket.to(roomId).emit('typing', {
      name: socket.userName,
      isTyping
    });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    if (socket.currentRoom && socket.userName) {
      const roomId = socket.currentRoom;
      socket.to(roomId).emit('user-left', { name: socket.userName });
      updateOnlineCount(roomId);
    }
  });
});

// Initialize previews and start server
initRoomPreviews().then(() => {
  server.listen(PORT, () => {
    console.log(`NexTalk server running on port ${PORT}`);
  });
});