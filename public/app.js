const socket = io();
const usernameInput = document.getElementById('usernameInput');
const registerBtn = document.getElementById('registerBtn');
const userList = document.getElementById('userList');
const messagesEl = document.getElementById('messages');
const chatHeader = document.getElementById('chatHeader');
const chatStatus = document.getElementById('chatStatus');
const messageForm = document.getElementById('messageForm');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');

let username = null;
let ownKeyPair = null;
let ownPublicKeyJwk = null;
let currentPartner = null;
let sharedSecrets = {};
let pendingKeyExchange = {};

registerBtn.addEventListener('click', async () => {
  const value = usernameInput.value.trim();
  if (!value) return;
  username = value;

  registerBtn.disabled = true;
  usernameInput.disabled = true;
  chatStatus.textContent = 'Generating secure key pair...';

  ownKeyPair = await generateECDHKeyPair();
  ownPublicKeyJwk = await exportPublicKeyJwk(ownKeyPair.publicKey);

  socket.emit('register', { username });
  chatStatus.textContent = 'Connected. Choose a user to start encrypted chat.';
});

socket.on('active-users', (users) => {
  renderUserList(users.filter((user) => user.username !== username));
});

socket.on('public-key', async ({ fromId, publicKey, username: partnerName }) => {
  if (!ownKeyPair) return;
  const partnerKey = await importPublicKeyJwk(publicKey);
  await deriveSharedSecret(fromId, partnerKey);

  if (!pendingKeyExchange[fromId]) {
    pendingKeyExchange[fromId] = true;
    socket.emit('public-key', { targetId: fromId, publicKey: ownPublicKeyJwk });
  }

  if (currentPartner?.id === fromId) {
    chatStatus.textContent = `Secure channel established with ${partnerName}.`;
  }
});

socket.on('encrypted-message', async ({ fromId, username: partnerName, iv, ciphertext }) => {
  const secret = sharedSecrets[fromId];
  if (!secret) {
    appendMessage('System', 'Received encrypted message before key exchange. Waiting for key handshake.');
    return;
  }

  try {
    const plaintext = await decryptMessage(secret, iv, ciphertext);
    appendMessage(partnerName || 'Partner', plaintext);
  } catch (error) {
    appendMessage('System', 'Failed to decrypt message. Message may be tampered with.');
    console.error(error);
  }
});

messageForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!currentPartner) return;
  const text = messageInput.value.trim();
  if (!text) return;

  const secret = sharedSecrets[currentPartner.id];
  if (!secret) {
    appendMessage('System', 'Key exchange not complete. Please wait.');
    return;
  }

  const { iv, ciphertext } = await encryptMessage(secret, text);
  socket.emit('encrypted-message', {
    targetId: currentPartner.id,
    iv,
    ciphertext,
  });

  appendMessage('You', text, true);
  messageInput.value = '';
});

function renderUserList(users) {
  userList.innerHTML = '';
  if (!username) return;
  if (users.length === 0) {
    userList.innerHTML = '<li class="text-slate-500">No other users online.</li>';
    return;
  }

  users.forEach((user) => {
    const li = document.createElement('li');
    li.className = 'rounded-3xl border border-slate-700 bg-slate-950 p-4 cursor-pointer hover:border-cyan-500 transition';
    li.innerHTML = `
      <div class="font-semibold text-slate-100">${escapeHtml(user.username)}</div>
      <div class="text-slate-500 text-sm">${user.id === currentPartner?.id ? 'Selected' : 'Click to chat'}</div>
    `;
    li.addEventListener('click', () => selectPartner(user));
    userList.appendChild(li);
  });
}

function selectPartner(user) {
  currentPartner = user;
  chatHeader.textContent = `Chat with ${user.username}`;
  chatStatus.textContent = 'Establishing secure channel...';
  messageInput.disabled = false;
  sendBtn.disabled = false;
  appendMessage('System', `Starting key exchange with ${user.username}.`);

  if (!sharedSecrets[user.id]) {
    socket.emit('public-key', { targetId: user.id, publicKey: ownPublicKeyJwk });
  }
}

function appendMessage(author, text, isOwn = false) {
  const wrapper = document.createElement('div');
  wrapper.className = `space-y-2 ${isOwn ? 'self-end text-right' : 'self-start'}`;
  wrapper.innerHTML = `
    <div class="text-slate-400 text-xs">${escapeHtml(author)}</div>
    <div class="inline-block rounded-3xl px-4 py-3 ${isOwn ? 'bg-cyan-500 text-slate-950' : 'bg-slate-700 text-slate-100'}">${escapeHtml(text)}</div>
  `;
  messagesEl.appendChild(wrapper);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function generateECDHKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey']
  );
}

async function exportPublicKeyJwk(publicKey) {
  return await crypto.subtle.exportKey('jwk', publicKey);
}

async function importPublicKeyJwk(jwk) {
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );
}

async function deriveSharedSecret(peerPublicKey) {
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    ownKeyPair.privateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );

  const partnerId = Object.values(sharedSecrets).findIndex((entry) => false); // no-op placeholder
  return derivedKey;
}

async function deriveSharedSecret(id, peerPublicKey) {
  const symmetricKey = await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    ownKeyPair.privateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
  sharedSecrets[id] = symmetricKey;
  return symmetricKey;
}

async function encryptMessage(key, text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    data
  );
  return {
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(encrypted),
  };
}

async function decryptMessage(key, ivBase64, ciphertextBase64) {
  const iv = base64ToBuffer(ivBase64);
  const ciphertext = base64ToBuffer(ciphertextBase64);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
