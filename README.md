# Secure Chat App

A real-time End-to-End Encrypted chat application using Node.js, Socket.io, and the Web Crypto API.

## Architecture

- The server in `server.js` is a blind relay.
- Users register with a username and connect via Socket.io.
- Each client generates an ECDH key pair locally in the browser.
- Public keys are exchanged through the server.
- Each client derives a shared AES-GCM key from its private ECDH key and the partner's public ECDH key.
- All chat messages are encrypted locally with AES-GCM before being sent.
- The server only forwards encrypted payloads and public keys.
- The server never stores or processes plaintext messages or private keys.

## ECDH Key Exchange Flow

1. Client A generates an ECDH key pair and registers with the server.
2. Client B does the same.
3. When A chooses B, A sends its public key to B via the server.
4. B receives A's public key and derives a shared AES-GCM key using B's private key.
5. B sends its public key back to A.
6. A derives the same shared AES-GCM key from A's private key and B's public key.
7. Both clients now share a symmetric key for AES-GCM encryption.

## Why the Server Cannot Read Messages

- The server only transports public keys and encrypted message payloads.
- Private keys remain on the client and are never sent to the server.
- AES-GCM encryption includes a built-in authentication tag, so tampering is rejected on decrypt.
- Because encryption and decryption happen entirely in the browser, the server cannot decrypt or inspect message content.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Start the server:

```bash
npm start
```

3. Open `http://localhost:3000` in two browser windows or tabs.

## Testing

- Enter a different username in each browser.
- Select the other user from the sidebar.
- Exchange messages.
- Messages are encrypted before leaving the browser and decrypted only by the recipient.
