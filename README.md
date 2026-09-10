# wicara

A terminal messenger where you add a contact by pasting a public key, not a phone
number. Chat, files and rooms travel directly peer to peer over hole-punched
QUIC. A small hub server holds ciphertext for recipients who are offline, and
nothing else — it cannot read a single message.

```
you ── QUIC/TLS 1.3, hole-punched ──────────────────────────────► your peer
 │        (falls back to an n0 relay that cannot read it)            │
 │                                                                   │
 └── when they are offline ──► wicara-hub ──── they come back ───────┘
                              (opaque bytes,
                               7-day TTL)
```

## Quick start

```sh
cargo install --git https://github.com/satyaadhiyaksaardy/wicara wicara
# or grab a binary from the Releases page

wicara id                       # prints your EndpointId — this is your address
wicara run                      # opens the chat UI and listens
wicara run --connect <their-id> # …and dials a peer whose id you pasted in
```

On first run wicara generates an Ed25519 keypair and asks for a passphrase. The
passphrase is stored nowhere. **If you lose it, your identity and your history
are gone — there is no reset, no recovery code, and no one to ask.** That is the
design, not an oversight.

### If you lose the passphrase

There is nothing to recover and no account to reset — your identity *is* the
keypair in that file, and only your passphrase decrypts it. What you can do is
start over, which means deleting the whole directory, not just the key:

```sh
rm -rf ~/.config/wicara            # Linux
rm -rf ~/Library/Application\ Support/wicara   # macOS
rmdir /s %APPDATA%\wicara          # Windows
```

Next run generates a fresh identity. You get a **new EndpointId**, so peers have
to add you again, and the old history stays unreadable forever.

Deleting only `identity.key` leaves a message store sealed under the old key.
wicara will tell you so and name the file rather than blaming your new
passphrase, but the fix is the same: remove the directory.

Inside the UI: click a peer, a message or the input bar, or press `tab` /
`shift-tab` to cycle them. In the chat pane `↑↓` picks a message and `r`
replies, `e` edits, `d` deletes and `1`–`5` react; the wheel scrolls.

While the mouse is captured your terminal cannot select text, so `/mouse` hands
it back when you want to copy something, and again to take it back. `/connect <id>` `/peers` `/whoami` `/nick <name>` `/send <path>`
`/room create <name>` `/room invite <id>` `/room kick <id>` `/quit`.

## Demo

[![asciicast](https://asciinema.org/a/1265096.svg)](https://asciinema.org/a/1265096)

Four machines on four networks, in one tmux window: a laptop, two lab servers —
one of them behind a NAT — and an arm64 Jetson. Every pane shows the other three
online over a direct hole-punched path, and the messages, the reaction and the
reply travel between them with no server involved.

`demo.cast` in the repo follows one terminal more closely: unlocking the
identity, dialling a peer by pasted key, and a file arriving with its BLAKE3
shown on both screens.

Both are text rather than video, so you can select and copy out of them, and
both are in the repo — `asciinema play demo-four-machines.cast` works offline.
IP addresses are redacted; nothing else is edited.

## How it is put together

Three crates in one workspace:

| | |
|---|---|
| `wicara-core` | wire types, the message-id scheme, at-rest crypto, the offline-message crypto, the room log |
| `wicara` | the client: iroh endpoint, encrypted sqlite store, ratatui UI |
| `wicara-hub` | the server: prekey directory, mailbox, room registry |

Peers you have talked to before are redialled automatically every 20 seconds
while they are not connected, so coming back online is enough — you do not have
to re-add anyone.

**Your identity is an Ed25519 keypair, and it is also your iroh EndpointId.**
There is no discovery server for 1:1 chat: iroh dials keys, not IP addresses,
and resolves the address itself. iroh reports about 95% of connections ending up direct; the
rest fall back to a relay, which forwards packets it cannot read. Try
`--relay-only` to see the fallback work.

**There are two layers of encryption and they do different jobs.**

* **iroh's QUIC/TLS 1.3** authenticates both ends by their Ed25519 keys and is
  genuinely end to end, *including over a relay*. All live chat, direct or
  relayed, is covered by this alone. It is not merely "transport security".
* **The application layer** (X25519 + ChaCha20-Poly1305) exists for exactly one
  reason: a message that has to sit on the hub while the recipient is offline.
  It has no job on a live connection.

Which is why the honest proof that the second layer works is not a packet
capture — TLS would give you that result with the layer deleted. It is opening
the hub's own database and finding the row unreadable.

**Offline messages use a signed prekey.** Each client publishes an X25519 prekey
signed by its Ed25519 identity key. Before using one, the sender verifies that
signature against the recipient's EndpointId. Skip that check and the hub can
substitute its own key and read everything; here it is not skippable, because
`SignedPrekey::verify` is the only way to obtain the type that `seal` accepts.
Every message then gets a fresh ephemeral X25519 keypair, which gives forward
secrecy on the sender's side.

**Rooms are a signed, hash-chained membership log.** Each op — create, invite,
kick — is signed by an admin and names the hash of the op before it. Clients
replay and verify the whole chain, so whoever hands it over is not trusted: the
hub can withhold a log but cannot forge membership, and neither can a peer.

Because the log carries its own proof, an invite carries the log itself rather
than a pointer to it. **Rooms between connected peers need no server at all**,
and a hub outage degrades them — no new members while you are apart — instead of
breaking them. The hub is for reaching someone who is not there: it is where an
offline member finds the room when they return. Room messages are encrypted
pairwise to each member, which is fine to roughly twenty of them.

**Attachments** go over their own QUIC stream in 64 KiB chunks with a BLAKE3
hash checked on arrival. A file that does not match is deleted, not kept, and
the announced size is refused above 256 MiB before a byte is written — the hash
can only be checked once the stream ends, so a limit that ran afterwards would
be a limit on nothing.

**At rest**, the identity file and every message body are encrypted with
XChaCha20-Poly1305 under a key derived from your passphrase with Argon2id. Not
SQLCipher — that is a C dependency that fights the Windows build for a job the
application already does.

## Running without a server

The hub is optional, and most of wicara does not involve it. Leave `--hub` off
and there is no server anywhere in the picture — not for chat, not for files,
not for rooms.

| without `--hub` | |
|---|---|
| Live 1:1 chat, direct or relayed | works |
| History, encrypted at rest | works |
| File transfer with BLAKE3 checks | works |
| Rooms: create, invite, kick, message | works, between connected peers |
| Messaging someone who is **offline** | needs the hub |
| Being invited to a room while **away** | needs the hub |

The pattern is one line: **the hub is for reaching someone who is not there.**
Everything that happens between two people who are both online happens between
them.

That is why a room invite carries the membership log instead of a pointer to
it. The log proves itself — every op signed, every op naming the hash before it
— so it does not matter who hands it over, and there is no reason to make a
server do it. A hub outage costs you new members while you are apart, not the
room.

The relay is a separate thing and is not a server in this sense: it forwards
sealed packets for peers whose NATs will not cooperate, holds nothing, and is
used by roughly one connection in twenty. See the threat model for what it does
learn.

## Threat model

Being exact about this is the point of the project, so here is the whole of it.

**Protected**

| | |
|---|---|
| Message content | from everyone except the sender and the recipient — the hub and the relay included |
| Local history and identity key | at rest, behind your passphrase |
| Room membership integrity | the hub cannot forge an invite or a kick, and a member can only ever sign *themselves* out |
| Message authorship | an op is only accepted under the key that authenticated, live or by mailbox |
| Attachment integrity | BLAKE3, checked before the file is kept |
| Display-name impersonation | a name you set outranks any name a peer claims, and unset names are marked `?` rather than shown as fact |

**Not protected — plainly**

| | |
|---|---|
| **Your IP address** | visible to any peer you connect to directly. Inherent to P2P, not a bug. |
| **The social graph, at the hub** | it learns who mails whom, when, and how large the message was. |
| **The social graph, at the relay** | the relay operator learns which EndpointIds talk and when, though not what they say. |
| **Post-compromise security** | none. A stolen identity key exposes future messages until it is rotated. Forward secrecy protects past mailbox messages only. |
| **Availability of offline delivery** | the hub is a single point of failure for it, and for room discovery. Live 1:1 chat keeps working without it. |
| **Mailbox flooding** | a keypair is free, so a determined attacker can mint identities and fill a mailbox up to its per-recipient cap. The caps bound the damage; they do not prevent the attempt. |
| **Multiple devices** | one identity is one device. No sync. |

Run without `--hub` and the last three rows stop applying, because then there is
no server involved at all.

## Future work, and why not now

| | |
|---|---|
| Voice and video calls | real-time media is a different project's worth of work |
| Status / stories | a broadcast feed adds no signal to a messaging demo |
| Cloud backup | conflicts with the local-only data principle |
| Polls | same |
| Multi-device identity sync | one keypair is one device for this version |
| Anonymity, Tor-style IP hiding | direct P2P means peers see each other's addresses, by design |
| Double Ratchet | prekeys give forward secrecy; a full ratchet is a research project, and a half-built one is worse than none |
| DHT room discovery | rooms here are small and explicit |
| Live audio recording | cross-platform capture collides with the Windows and macOS builds |
| LoRa / radio mesh | a future project |
| Homebrew tap, apt repo, Scoop bucket | signing keys and repo metadata to keep alive, for what `cargo install --git` and a release download already do |

## Running your own hub

```sh
cargo run -p wicara-hub -- --listen 127.0.0.1:8787 --db wicara-hub.db
wicara run --hub http://127.0.0.1:8787
```

It is an `axum` + `rusqlite` service with three jobs and no others: a prekey
directory, a mailbox with a 7-day TTL and a per-sender quota, and a room
registry. Mailbox reads are authenticated by a signature over `(endpoint,
timestamp)` with a five-minute window. Put it behind a Cloudflare Tunnel if you
want it reachable; the client polls rather than holding a connection open, so
Cloudflare's 100-second idle cutoff has nothing to cut.

## Development

```sh
cargo test              # unit checks: crypto, framing, the room log, the fold, the UI
cargo clippy --all-targets
```

Every milestone was signed off by running the real binaries, not by unit tests.
The checks that exist are the small ones that fail loudly if a specific rule
breaks: a prekey signed by the wrong key, a forged room entry, an edit of
someone else's message, a peer choosing where its file lands.

## Licence

MIT.
