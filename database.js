const fs = require('fs').promises;
const path = require('path');

const dbPath = path.join(__dirname, 'db.json');

const defaultData = {
  users: [],
  messages: {} // roomId -> Array of message objects
};

// Internal cache to avoid continuous reading
let dbCache = null;

// Initialize database file if it doesn't exist
async function initDb() {
  try {
    await fs.access(dbPath);
  } catch (err) {
    // File doesn't exist, create it with default structure
    await fs.writeFile(dbPath, JSON.stringify(defaultData, null, 2), 'utf8');
  }
}

// Load full data
async function loadData() {
  if (dbCache) return dbCache;
  await initDb();
  try {
    const content = await fs.readFile(dbPath, 'utf8');
    dbCache = JSON.parse(content);
    return dbCache;
  } catch (err) {
    console.error('Error loading database, resetting cache to defaults:', err);
    dbCache = JSON.parse(JSON.stringify(defaultData));
    return dbCache;
  }
}

// Save full data
async function saveData() {
  if (!dbCache) return;
  try {
    await fs.writeFile(dbPath, JSON.stringify(dbCache, null, 2), 'utf8');
  } catch (err) {
    console.error('Error writing to database:', err);
  }
}

// Helper methods
async function getUserByEmail(email) {
  const data = await loadData();
  const lowerEmail = email.trim().toLowerCase();
  return data.users.find(u => u.email.toLowerCase() === lowerEmail);
}

async function addUser(name, email, passwordHash) {
  const data = await loadData();
  const newUser = {
    id: Date.now().toString(),
    name: name.trim(),
    email: email.trim().toLowerCase(),
    passwordHash
  };
  data.users.push(newUser);
  await saveData();
  return newUser;
}

async function getMessages(roomId) {
  const data = await loadData();
  return data.messages[roomId] || [];
}

async function addMessage(roomId, message) {
  const data = await loadData();
  if (!data.messages[roomId]) {
    data.messages[roomId] = [];
  }
  data.messages[roomId].push(message);
  await saveData();
}

module.exports = {
  loadData,
  getUserByEmail,
  addUser,
  getMessages,
  addMessage
};