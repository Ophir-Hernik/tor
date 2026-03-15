// TOR Project Documentation (comment-only .cpp)
// -----------------------------------------------------------------------------
// This file intentionally contains ONLY comments. It is meant to be kept inside
// the repository as a readable, compiler-ignored explanation of how the project
// works and how the common/ folder is organized.
//
// The goal is to explain the system like a person would explain it to a teammate:
// what each file is for, why it exists, how it is used, and how the pieces fit.
//
// Note about style:
// - I am using simple ASCII punctuation and characters that exist on a keyboard.
// - I avoid fancy bullets or special symbols.
// - This is not a formal spec; it is a deep "walkthrough with rationale".
//
// -----------------------------------------------------------------------------
// 0) Big picture: what the system is today
// -----------------------------------------------------------------------------
//
// You have 3 hop "TOR-like" routing as a learning project:
//
//   Client  ->  Guard  ->  Middle  ->  Exit
//   (TCP)      (TCP)      (TCP)       (TCP)
//
// Important honesty about privacy:
// - On the wire, every hop is encrypted (AES-CTR + HMAC in this project).
// - But each hop decrypts what it receives before forwarding, then re-encrypts
//   toward the next hop. That means Guard and Middle do have the plaintext in
//   memory while they are relaying.
// - Real Tor onion routing is different: the client wraps multiple layers of
//   encryption so that intermediate hops can only remove their own layer and
//   still do not learn the original payload.
// - For now, the hop-by-hop design is a good stepping stone because it is much
//   simpler to debug and prove correctness.
//
// Each link uses a "SecureChannel":
// - First do an authenticated key exchange (handshake).
// - Derive session keys (AES-CTR keys + IVs, plus MAC keys).
// - Then send framed packets over TCP. Each packet is:
//     [u32 length][ciphertext bytes][HMAC tag (32 bytes)]
// - The receiving side verifies the HMAC before decrypting.
//
// In plain terms:
// - packet.cpp gives you clean message boundaries on top of TCP.
// - handshake.cpp gives you an authenticated shared secret.
// - kdf.cpp turns the shared secret into "the keys we need".
// - secure_channel.cpp combines framing + encryption + authentication.
// - node mains (Guard/Middle/Exit) glue it all together into a relay.
//
// -----------------------------------------------------------------------------
// 1) Data flow during a normal session (high-level story)
// -----------------------------------------------------------------------------
//
// 1. Exit starts listening on some port (default 9002).
// 2. Middle starts listening (default 9001) and knows how to connect to Exit.
// 3. Guard starts listening (default 9000) and knows how to connect to Middle.
// 4. Client connects to Guard.
//
// Now the interesting part happens:
//
// - Guard accepts the client socket as "inbound".
// - Guard opens an "outbound" socket to Middle.
// - Guard runs handshake_as_server on inbound (client is the "client").
// - Guard runs handshake_as_client on outbound (guard is the "client" toward middle).
// - Guard now has two SecureChannel objects:
//     chIn  (client <-> guard)
//     chOut (guard  <-> middle)
//
// - Guard starts two relay threads:
//     inbound -> outbound (forward direction)
//     outbound -> inbound (backward direction)
//
// Middle does the same pattern between Guard and Exit.
// Exit does handshake_as_server and then handles messages.
//
// When a connection closes or errors:
// - recv_plain throws.
// - relay thread catches, sets a shared stop flag, and shuts down sockets.
// - The session ends.
// - The node main goes back to accept() and waits for another session.
//
// -----------------------------------------------------------------------------
// 2) How the "common/" folder is structured
// -----------------------------------------------------------------------------
//
// common/include contains headers: public interfaces, class declarations,
// function prototypes, and small inline helpers.
//
// common/src contains implementations: actual logic for the interfaces.
//
// The folder is split into 3 main areas:
// 1) crypto/    primitives and helpers for ECDH, AES-CTR, hashes, RSA auth, etc.
// 2) net/       a tiny Socket wrapper over WinSock
// 3) protocol/  packet framing and handshake logic
//
// Finally there is secure_channel.* at the root of common, because it is the
// main "glue object" that joins protocol + crypto + net.
//
// -----------------------------------------------------------------------------
// 3) File-by-file explanation (each file has its own section)
// -----------------------------------------------------------------------------
//
// I am listing every file under common/include and common/src.
//
// To keep it readable, each header and its .cpp have separate sections,
// even when they form a pair.
//
// ============================================================================
// File: common/include/net/socket.h
// ============================================================================
//
// Purpose:
// - Provide a small RAII wrapper around a WinSock SOCKET.
// - Hide platform details from the rest of the code.
// - Offer a small, predictable API: connect, listen, accept, send_all, recv_all.
//
// Main ideas:
// - TCP is a byte stream. It does not preserve message boundaries.
// - You still need a clean "send all bytes / receive exact bytes" helper.
// - This file is the central place that ensures "recv until we got N bytes".
//
// Main pieces you should expect in the interface:
// - winsock_init() to call WSAStartup once early in the program.
// - listen_tcp(port) to create/bind/listen.
// - accept(listener) to accept an inbound connection.
// - connect_tcp(host, port) to create an outbound connection.
// - send_all(data, len) loops until all bytes are sent.
// - recv_all(data, len) loops until all bytes are received, or throws on error.
// - shutdown_both() (if present) is used to break blocking calls on the other side.
// - set_timeouts_ms() helps prevent infinite blocking when a peer disappears.
//
// Why the name "socket":
// - It is not fancy. It is exactly what it wraps.
// - Keeping the name simple helps future contributors quickly find it.
//
// ============================================================================
// File: common/src/net/socket.cpp
// ============================================================================
//
// Purpose:
// - Implement the Socket wrapper using WinSock2 functions.
// - Centralize error handling and the "retry until complete" loops.
//
// Notable behaviors:
// - send_all: calls send() repeatedly until the entire buffer is written.
//   This is necessary because send() may send fewer bytes than requested.
// - recv_all: calls recv() repeatedly until the entire buffer is filled.
//   This is necessary because recv() may return fewer bytes than requested.
// - recv_all treats "0 bytes" as "peer closed connection", which becomes an
//   exception. That is the right choice for your relay loops: it ends the session.
// - set_timeouts_ms uses setsockopt with SO_RCVTIMEO and SO_SNDTIMEO.
//
// Design notes:
// - This code assumes Windows (WinSock) and uses Ws2_32.lib.
// - If you ever port to Linux, this is one of the files that would need a new
//   implementation (POSIX sockets).
//
// ============================================================================
// File: common/include/protocol/packet.h
// ============================================================================
//
// Purpose:
// - Provide a simple framing layer on top of TCP.
// - Convert "byte stream" into "messages".
//
// Frame format used here:
// - [4-byte length, big-endian][payload bytes...]
//
// Why it exists:
// - Without framing, reads would return arbitrary chunk sizes.
// - Handshake messages and secure messages would be impossible to parse safely.
//
// Why the name "packet":
// - It is not a real network packet (TCP already packets bytes under the hood).
// - It is an application-level packet: a framed message.
// - The name is short and common across many networking codebases.
//
// ============================================================================
// File: common/src/protocol/packet.cpp
// ============================================================================
//
// Purpose:
// - Implement send_packet and recv_packet using Socket::send_all / recv_all.
//
// Important safety behavior:
// - There is a hard cap on packet size (for example 1 MiB).
// - This prevents a malicious peer from sending a huge length and forcing the
//   program to allocate massive buffers (memory exhaustion).
//
// Why big-endian length:
// - Standard network byte order is big-endian.
// - It avoids confusion when different machines interpret integer bytes.
//
// ============================================================================
// File: common/include/protocol/handshake.h
// ============================================================================
//
// Purpose:
// - Define the interface for establishing per-link session keys.
// - Expose two entry points:
//     handshake_as_client(socket)
//     handshake_as_server(socket)
//
// Why two functions:
// - Client and server do symmetric-but-not-identical steps.
// - The initiator sends a "ClientHello" message (a binary struct, not the literal
//   word "hello").
// - The responder verifies it, replies with a "ServerHello" message, then both
//   sides derive keys.
//
// What the handshake produces:
// - A SessionKeys object (defined in crypto/kdf.h) with:
//     txKey, rxKey, txIv, rxIv, txMacKey, rxMacKey
// - These keys are used to construct a SecureChannel.
//
// ============================================================================
// File: common/src/protocol/handshake.cpp
// ============================================================================
//
// Purpose:
// - Implement an authenticated key exchange (AKE) for each hop.
// - Combine:
//     ECDH (for secrecy) + RSA signatures (for authentication) + SHA256 (for hashing)
//
// Message format used by the handshake (conceptually):
// - ClientHello:
//     type=1
//     nonceC (16 bytes)
//     pubC length + pubC blob (ECDH public key blob)
//     signature length + signature bytes
// - ServerHello:
//     type=2
//     nonceS (16 bytes)
//     pubS length + pubS blob
//     signature length + signature bytes
//
// What gets signed:
// - The code hashes a transcript with a short ASCII tag ("CHLO" or "SHLO").
// - Then signs that hash with the sender's RSA private key.
// - The receiver verifies the signature using a pinned RSA public key.
//
// How trust works today:
// - When acting as server, we verify the previous hop with pre_key.txt.
// - When acting as client, we verify the next hop with next_key.txt.
// - This is a simple, file-based pinning model.
// - Later, a directory server can provide the expected public keys instead.
//
// Why nonces exist:
// - They make transcripts unique and prevent trivial replay.
// - They also feed into the server transcript hash.
//
// Key derivation:
// - After ECDH, the shared secret is run through derive_session_keys in kdf.cpp.
// - That gives distinct keys for client-to-server and server-to-client.
//
// Important detail:
// - ECDH is ephemeral per session. That gives you forward secrecy for the link.
// - RSA keys are long-term identity keys. That gives you authentication.
//
// File naming:
// - "handshake" is a direct name. It is the "hello, prove who you are, derive keys"
//   phase that happens before normal traffic.
//
// ============================================================================
// File: common/include/crypto/ecdh.h
// ============================================================================
//
// Purpose:
// - Provide an ECDH key exchange interface.
// - Hide Windows BCrypt types from the rest of the project.
//
// What it represents:
// - ecdh_generate_p256 creates an ephemeral ECDH key pair.
// - ecdh_derive_shared_sha256 derives a shared secret from my private key and
//   the peer's public key, then produces a 32-byte value.
//
// Why it returns sha256(shared):
// - In this project, the code uses BCryptDeriveKey with SHA256 KDF.
// - The end result is a fixed 32-byte shared value that is easy to feed into kdf.cpp.
//
// Why P-256:
// - It is widely supported by Windows CNG/BCrypt.
// - It is not the newest curve, but it is common and stable for a demo.
//
// File naming:
// - "ecdh" is the standard acronym for Elliptic Curve Diffie Hellman.
// - Short, recognizable, and matches the primitive.
//
// ============================================================================
// File: common/src/crypto/ecdh.cpp
// ============================================================================
//
// Purpose:
// - Implement the ECDH functions using Windows BCrypt (CNG).
//
// Main flow in the implementation:
// - OpenAlgorithmProvider(ECDH_P256)
// - GenerateKeyPair(256)
// - ExportKey(public) as BCRYPT_ECCPUBLIC_BLOB
// - SecretAgreement(myPrivate, peerPublic)
// - DeriveKey using a SHA256-based KDF, producing 32 bytes
//
// Notable implementation detail:
// - The code must pass the KDF hash algorithm name correctly, including the null
//   terminator and correct byte size, because BCrypt expects a WCHAR string.
//
// Design note:
// - The private key is stored as an opaque handle (void*) and freed later.
// - That avoids leaking BCrypt types across the header boundary.
//
// ============================================================================
// File: common/include/crypto/sha256.h
// ============================================================================
//
// Purpose:
// - Provide SHA256 hashing as a simple function.
// - Used by handshake transcript hashing and by the local KDF logic.
//
// Why a separate file:
// - Many parts of the code need hashing.
// - Keeping it isolated makes it easy to swap implementations later if desired.
//
// ============================================================================
// File: common/src/crypto/sha256.cpp
// ============================================================================
//
// Purpose:
// - Implement SHA256 using Windows BCrypt.
//
// Notes:
// - This uses BCryptOpenAlgorithmProvider for SHA256.
// - It creates a hash object, feeds data, and finishes to 32 bytes.
//
// Practical reason to use BCrypt:
// - You get a correct implementation that is already on the system.
// - It avoids hand-rolled hash code that might be wrong.
//
// ============================================================================
// File: common/include/crypto/hmac.h
// ============================================================================
//
// Purpose:
// - Provide HMAC-SHA256 as a helper function.
// - Used by secure_channel.cpp to authenticate encrypted packets.
//
// Why HMAC exists in this design:
// - AES-CTR provides confidentiality only (it is malleable).
// - Without a MAC, an attacker can flip bits in ciphertext and cause predictable
//   bit flips in plaintext.
// - With HMAC verification, modified packets are rejected before decryption.
//
// ============================================================================
// File: common/src/crypto/hmac.cpp
// ============================================================================
//
// Purpose:
// - Implement HMAC-SHA256 using Windows BCrypt with the HMAC flag.
//
// Design note:
// - This implementation is straightforward and safe.
// - If performance becomes a concern, you can reuse algorithm providers/handles,
//   but correctness is the priority for now.
//
// ============================================================================
// File: common/include/crypto/kdf.h
// ============================================================================
//
// Purpose:
// - Define SessionKeys and provide derive_session_keys(shared, isClient).
//
// What SessionKeys contains:
// - txKey: 16 bytes AES key for sending
// - rxKey: 16 bytes AES key for receiving
// - txIv:  16 bytes base counter/IV for sending AES-CTR
// - rxIv:  16 bytes base counter/IV for receiving AES-CTR
// - txMacKey: 32 bytes MAC key for sending HMAC
// - rxMacKey: 32 bytes MAC key for receiving HMAC
//
// Why include both tx and rx:
// - Each direction should use independent keys.
// - Otherwise you risk weird reflection and cross-protocol issues.
//
// File naming:
// - "kdf" stands for Key Derivation Function.
// - This file is a local simplified KDF, not a full HKDF spec.
//
// ============================================================================
// File: common/src/crypto/kdf.cpp
// ============================================================================
//
// Purpose:
// - Implement derive_session_keys.
//
// How it works in this project:
// - It computes SHA256(shared || label) for several labels:
//     c2s_key, s2c_key, c2s_iv, s2c_iv, c2s_mac, s2c_mac
// - It then maps these into tx/rx fields depending on isClient.
//
// Why the labels exist:
// - They ensure different derived values even though the same shared secret is used.
// - It is a simple "domain separation" method.
//
// Important caveat:
// - This is not HKDF and does not use salt or extract/expand the HKDF way.
// - For a learning project, it is acceptable, but for real security you would
//   normally implement HKDF over the ECDH output.
//
// ============================================================================
// File: common/include/crypto/aes_adapter.h
// ============================================================================
//
// Purpose:
// - Define a tiny "AES block encryption" function:
//     aes128_encrypt_block(key16, in16, out16)
//
// Why an adapter exists:
// - The rest of the code wants "AES as a primitive" without caring if the
//   underlying implementation comes from a library, Windows, or custom code.
// - This file is the boundary where you can switch implementations.
//
// File naming:
// - "adapter" is a good name because it adapts a platform-specific AES provider
//   to a project-friendly function signature.
//
// ============================================================================
// File: common/src/crypto/aes_adapter.cpp
// ============================================================================
//
// Purpose:
// - Implement aes128_encrypt_block using Windows BCrypt AES (ECB, no padding).
//
// Why ECB is used here:
// - Only as a block primitive to build AES-CTR keystream blocks.
// - We are not using ECB as a message mode. That would be insecure.
// - CTR mode is built in aes_ctr.cpp by encrypting the counter blocks.
//
// Practical reason this file mattered:
// - The previous custom AES did not match standard AES output.
// - That broke interoperability with the Python test client.
// - BCrypt AES is correct and matches standard implementations.
//
// Implementation details:
// - Opens AES algorithm provider.
// - Sets chaining mode to ECB.
// - Generates a symmetric key handle.
// - Encrypts exactly 16 bytes.
// - Uses a per-thread cache so it is not painfully slow.
//
// ============================================================================
// File: common/include/crypto/aes_ctr.h
// ============================================================================
//
// Purpose:
// - Provide AES-CTR as a small class that can encrypt/decrypt byte vectors.
//
// Key idea about CTR:
// - Encryption and decryption are the same operation:
//     ciphertext = plaintext XOR keystream
// - The keystream is AES(key, counter), counter incremented each block.
//
// Why a class:
// - It needs to keep internal counter state as you stream through data.
// - That state must be different for tx and rx directions (different IVs).
//
// ============================================================================
// File: common/src/crypto/aes_ctr.cpp
// ============================================================================
//
// Purpose:
// - Implement the AES-CTR stream logic using aes128_encrypt_block from aes_adapter.
//
// Notable behavior:
// - It increments the last 8 bytes of the 16-byte counter block (big-endian).
// - That is a conventional choice, but it must match on both ends.
//
// Usability:
// - tx_.apply(data) encrypts in-place.
// - rx_.apply(data) decrypts in-place (same call).
//
// ============================================================================
// File: common/include/crypto/rsa_auth.h
// ============================================================================
//
// Purpose:
// - Provide a clean "sign hash32" and "verify hash32" interface for authentication.
// - This is used by handshake.cpp.
//
// Why this wrapper exists:
// - handshake.cpp should not care about key file formats or multiprecision math.
// - It should just say: sign this transcript hash, verify that signature.
//
// It also provides:
// - rsa_get_public_key_text() for printing/exporting the identity key in "e:n"
//   format, which is used for pinning.
//
// ============================================================================
// File: common/src/crypto/rsa_auth.cpp
// ============================================================================
//
// Purpose:
// - Implement RSA signing and verification using RSAEncryption.
// - Manage a single long-term RSA identity keypair for the process.
//
// Key management logic:
// - Load from "rsa_keypair.edn" (or an env override).
// - If missing, generate a new RSA keypair and write it.
// - If present but unreadable, fail unless an env flag allows regeneration.
//   This avoids silently changing identity, which would break trust pinning.
//
// Signature encoding choice:
// - The signature is stored as a decimal string representation of a big integer.
// - That is simple for debugging but not bandwidth-efficient.
// - For later improvements, you could store it as big-endian bytes.
//
// ============================================================================
// File: common/include/crypto/RSAEncryption.h
// ============================================================================
//
// Purpose:
// - Provide an RSA implementation using big integer math (Boost.Multiprecision).
// - Support key generation, sign, verify, and parse/export utilities.
//
// Why it exists in the repo:
// - Educational value and independence from external crypto libraries.
// - Also makes the project self-contained.
//
// Naming:
// - The name is explicit: RSAEncryption.
// - In a larger project, you might split this into rsa_core and rsa_keys,
//   but for this scale, one name is fine.
//
// ============================================================================
// File: common/src/crypto/RSAEncryption.cpp
// ============================================================================
//
// Purpose:
// - Implement the RSA math: modular exponentiation, key generation, parsing,
//   signing and verification.
//
// Caution:
// - Writing RSA by hand is easy to get wrong for real-world use.
// - This project uses it mainly for identity signatures of handshake transcripts.
// - In production-grade systems, RSA would normally come from a vetted library.
//
// ============================================================================
// File: common/include/crypto/AESEncryption.h
// ============================================================================
//
// Purpose:
// - Legacy or educational AES implementation interface.
//
// Important note for the current build:
// - The project now uses Windows BCrypt AES through aes_adapter.cpp for the actual
//   AES block primitive in AES-CTR.
// - That means AESEncryption.* is no longer part of the critical encryption path.
//
// Why keep it:
// - It can be useful for learning and comparing behavior.
// - You can remove it later if you want to reduce code surface.
//
// ============================================================================
// File: common/src/crypto/AESEncryption.cpp
// ============================================================================
//
// Purpose:
// - Implementation of the legacy/custom AES.
// - It is kept in the repo but is not the active AES used for the secure channel.
//
// ============================================================================
// File: common/include/crypto/EncryptionAlgorithm.h
// ============================================================================
//
// Purpose:
// - A small abstraction that existed to represent encryption algorithms in a
//   more generic way.
// - Depending on the rest of the code, it may or may not be actively used now.
//
// Why such a file can exist:
// - When a project grows, having a "common interface" for crypto algorithms can
//   reduce coupling.
// - For a small project, it can also be overkill, but it is not harmful.
//
// ============================================================================
// File: common/include/secure_channel.h
// ============================================================================
//
// Purpose:
// - Define the SecureChannel class: the main reusable "secure pipe" abstraction.
//
// What SecureChannel does for callers:
// - send_plain(plaintext bytes)
// - recv_plain() returns plaintext bytes
//
// What it hides:
// - Packet framing (protocol/packet.*)
// - Encryption and decryption (crypto/aes_ctr.*)
// - Integrity/authentication (crypto/hmac.*)
//
// Why this class is central:
// - Node mains become simple relay code.
// - They do not need to care about packet structure or crypto details.
//
// ============================================================================
// File: common/src/secure_channel.cpp
// ============================================================================
//
// Purpose:
// - Implement SecureChannel.
//
// Actual on-wire format for a SecureChannel message:
// - The SecureChannel encrypts plaintext to ciphertext using AES-CTR.
// - It computes tag = HMAC-SHA256(macKey, len_be(cipherLen) || ciphertext).
// - It sends one framed packet containing ciphertext || tag.
// - recv_plain reverses it: receive packet, check tag, then decrypt.
//
// Why HMAC includes the length:
// - It binds the ciphertext length to the tag.
// - It prevents certain framing confusion attacks where length could be altered.
//
// Constant-time compare:
// - The code compares the expected tag and received tag in constant time to avoid
//   leaking information through timing. That is a good habit.
//
// -----------------------------------------------------------------------------
// 4) Quick note on the node-specific files outside common/
// -----------------------------------------------------------------------------
//
// Your node mains (GuardNode/main_guard.cpp, MiddleNode/main_middle.cpp,
// ExitNode/main_exit.cpp) are responsible for wiring:
//
// - listen/accept/connect
// - handshake on each link
// - constructing SecureChannel objects
// - running relay loops
//
// The common/ folder is written so that these mains can be short and readable.
//
// -----------------------------------------------------------------------------
// End of comment-only documentation.
// -----------------------------------------------------------------------------
// (If you want, you can extend this file later with a section that documents
// the directory server integration once it exists.)
