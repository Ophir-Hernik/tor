/*
###   MiddleNode - documentary_file.cpp
###   This file contains high-level explanations about the MiddleNode project,
###   its purpose in Sprint 2, the file structure, and the design decisions behind
###   the Diffie-Hellman + encrypted relay pipeline.
###
###   This file is intentionally ALL COMMENTS to help new contributors / graders
###   understand the project quickly.

================================================================================
Project: MiddleNode (Sprint 2)
================================================================================

Goal (Sprint 2)
---------------
Implement a TOR "Middle Node" that sits between:
    Guard  <---->  MiddleNode  <---->  Next Hop (later Exit / or dummy exit)

The Middle Node must:
1) Accept inbound TCP from Guard.
2) Open outbound TCP to the next hop.
3) Perform a Diffie-Hellman key exchange on BOTH links (inbound and outbound).
4) Derive symmetric session keys from DH shared secrets.
5) Relay traffic bi-directionally:
       inbound:  recv from Guard  -> decrypt -> encrypt -> send to next hop
       outbound: recv from next   -> decrypt -> encrypt -> send to Guard

Important note (security)
-------------------------
DH alone provides a shared key BUT does not authenticate the peer.
That means a man-in-the-middle could theoretically intercept the DH exchange.
In real TOR, key exchange is authenticated. In our project:
- Sprint 2 focus is: DH + per-link symmetric encryption + relay
- Authentication can be added later (e.g., sign DH public value with RSA).

================================================================================
High-level architecture
================================================================================

We split the MiddleNode into clear layers:

1) net/Socket: TCP connect/listen/accept + send_all/recv_all
2) protocol/Packet: message framing (length prefix)
3) protocol/Handshake: DH key exchange messages (client hello / server hello)
4) crypto: ECDH + KDF + AES-CTR wrapper (encrypt/decrypt)
5) SecureChannel: ties (Socket + session keys) into a read/write of plaintext
6) Relay: forwards plaintext from one channel into the other (and vice-versa)
7) main: creates inbound/outbound links, performs both handshakes, starts relay

================================================================================
Folder / file structure (MiddleNode)
================================================================================

MiddleNode/
  include/
    net/
      socket.h
    protocol/
      packet.h
      handshake.h
    crypto/
      ecdh.h
      sha256.h
      kdf.h
      aes_adapter.h
      aes_ctr.h
    secure_channel.h

  src/
    net/socket.cpp
    protocol/packet.cpp
    protocol/handshake.cpp
    crypto/ecdh.cpp
    crypto/sha256.cpp
    crypto/kdf.cpp
    crypto/aes_adapter.cpp
    crypto/aes_ctr.cpp
    secure_channel.cpp
    main.cpp

  config/
    middleNode.json   (optional future enhancement: ports/hosts config)

================================================================================
How MiddleNode communicates (Protocol)
================================================================================

We use a very simple message framing so parsing is predictable:
Frame format:
    [ 4 bytes big-endian length ][ payload bytes... ]

This framing is implemented in protocol/packet.h/.cpp
(Alternatively, the project can reuse Sprint1 frame_codec; packet framing is the same idea.)

-------------------
Handshake messages
-------------------
We define two message types for DH exchange:
    1 = CLIENT_HELLO
    2 = SERVER_HELLO

Payload format for handshake frames:
    CLIENT_HELLO: [1][client_public_blob...]
    SERVER_HELLO: [2][server_public_blob...]

In the current implementation we use Windows CNG ECDH P-256, and exchange the
BCRYPT_ECCPUBLIC_BLOB form of the public key.

Handshake roles:
- Middle is SERVER on inbound (Guard -> Middle)
- Middle is CLIENT on outbound (Middle -> NextHop)

So:
Inbound (Guard connects):
    Guard sends CLIENT_HELLO
    Middle replies SERVER_HELLO
Outbound (Middle connects to next hop):
    Middle sends CLIENT_HELLO
    NextHop replies SERVER_HELLO

After exchanging public keys, both sides compute the same shared secret.

================================================================================
Key derivation and session keys
================================================================================

The raw shared secret is not used directly as an AES key.
We derive session keys from the shared secret:

We derive:
- txKey (AES-128 key for sending)
- rxKey (AES-128 key for receiving)
- txIv  (CTR initial counter base for sending)
- rxIv  (CTR initial counter base for receiving)

Derivation approach used:
- Shared secret -> (KDF_HASH / SHA256 inside CNG) produces 32 bytes
- Then we compute labeled SHA-256 expansions:
    SHA256(shared || "c2s_key"), SHA256(shared || "s2c_key")
    SHA256(shared || "c2s_iv"),  SHA256(shared || "s2c_iv")
- Each key/iv uses the first 16 bytes of the respective digest.

We also differentiate client vs server so both sides match directions:
- client uses c2s for tx and s2c for rx
- server uses s2c for tx and c2s for rx

This is implemented in crypto/kdf.h/.cpp

================================================================================
Encryption mode (AES-CTR)
================================================================================

We use AES-CTR for stream encryption:
- encryption/decryption are identical (XOR with keystream)
- works with any length payload
- easy to implement using block encryption primitive (AES-ECB on counter blocks)

Implementation:
- aes_ctr.h/.cpp implements CTR stream application
- aes_adapter.h/.cpp supplies AES-128 block encrypt

Important practical note:
- The AES code your teammate wrote may be a "block cipher only".
  If so, we can still use it as the block primitive for CTR.
- In our implementation, aes_adapter currently uses Windows CNG AES-ECB block encrypt.
  If we want to use teammate AES instead, we only modify aes_adapter.cpp and keep all
  CTR/channel logic identical.

================================================================================
SecureChannel abstraction
================================================================================

secure_channel.h/.cpp wraps:
- a Socket
- session keys (tx/rx)
- AES-CTR state

It exposes:
- send_plain(plaintext_vector)
- recv_plain() -> plaintext_vector

Internally it:
- encrypts plaintext -> ciphertext
- frames it using protocol/packet (len+payload)
- sends it over TCP
and for receiving:
- reads framed ciphertext
- decrypts using rx stream
- returns plaintext

This is key: Relay code never deals with encryption directly; it forwards plaintext
between two SecureChannels.

================================================================================
Relay logic (Middle node core behavior)
================================================================================

Middle node needs full-duplex relay (both directions at once):
- Thread A: inbound -> outbound
- Thread B: outbound -> inbound

Each thread loops:
    p = in.recv_plain()
    out.send_plain(p)

If either thread hits:
- disconnect
- malformed packet
- crypto failure
it sets stop flag and ends the relay.

This is implemented in main.cpp as relay_loop, but can be moved into relay.cpp if desired.

================================================================================
main.cpp flow (Sprint 2)
================================================================================

main.cpp typically does:

1) winsock_init()
2) listener = listen_tcp(listenPort)
3) inbound  = accept(listener)              // Guard connects
4) outbound = connect_tcp(nextHost,nextPort) // connect forward
5) inKeys  = handshake_as_server(inbound)   // DH for inbound link
6) outKeys = handshake_as_client(outbound)  // DH for outbound link
7) create SecureChannel(inbound, inKeys) and SecureChannel(outbound, outKeys)
8) start two relay threads
9) join threads, exit

================================================================================
Testing plan (recommended)
================================================================================

Because we may not yet have a full Exit node:
- create a simple DummyExit project listening on 9002
- it does handshake_as_server(), then echoes plaintext packets back

Test scenario:
1) start DummyExit on port 9002
2) start MiddleNode on port 9001
3) start Guard and connect to MiddleNode:9001
4) send a message from Guard -> it should pass through MiddleNode -> DummyExit -> return

This verifies:
- handshake correctness
- symmetric encryption/decryption correctness
- relay correctness

================================================================================
Notes about Visual Studio integration
================================================================================

- All projects live under one .sln (TorNetwork.sln).
- You can run multiple nodes at once:
    Solution -> Properties -> Startup Project -> Multiple startup projects.
- MiddleNode requires linking:
    Ws2_32.lib  (winsock)
    Bcrypt.lib  (CNG crypto: SHA256, ECDH, AES-ECB)

================================================================================
Files summary (by importance)
================================================================================

net/socket.*:
- raw TCP building block (connect, listen, accept, send_all, recv_all)

protocol/packet.*:
- stable framing so we can send variable length payloads safely

protocol/handshake.*:
- runs ECDH exchange and outputs derived SessionKeys

crypto/ecdh.*:
- uses Windows CNG ECDH P-256 to generate keypair and derive shared secret

crypto/kdf.*:
- converts shared secret into directional AES keys and IVs

crypto/aes_adapter.*:
- one block AES encrypt primitive (Windows AES-ECB by default)
- can later be replaced by teammate AES block implementation

crypto/aes_ctr.*:
- encrypt/decrypt stream using AES-CTR

secure_channel.*:
- high-level encrypted channel used by relay

main.cpp:
- wires everything together, starts relay

================================================================================
End of documentary file
================================================================================
*/
