const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const users = new Map(); // track active users by socket id

app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
  socket.on('register', ({ username }) => {
    if (!username || typeof username !== 'string') {
      socket.disconnect(true);
      return;
    }
    users.set(socket.id, { username });
    io.emit('active-users', getActiveUsers());
  });

  socket.on('public-key', ({ targetId, publicKey }) => {
    if (!users.has(targetId)) return;
    io.to(targetId).emit('public-key', {
      fromId: socket.id,
      publicKey,
      username: users.get(socket.id)?.username,
    });
  });

  socket.on('encrypted-message', ({ targetId, iv, ciphertext }) => {
    if (!users.has(targetId)) return;
    io.to(targetId).emit('encrypted-message', {
      fromId: socket.id,
      username: users.get(socket.id)?.username,
      iv,
      ciphertext,
    });
  });

  socket.on('disconnect', () => {
    users.delete(socket.id);
    io.emit('active-users', getActiveUsers());
  });
});

function getActiveUsers() {
  return Array.from(users.entries()).map(([id, { username }]) => ({ id, username }));
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Secure chat server listening on http://localhost:${PORT}`);
});
