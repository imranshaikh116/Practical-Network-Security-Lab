# 10 — Cryptography Abuse: Hashes, Password Recovery, Encryption, and TLS Review

## Concept first: cryptography is about trust, not magic

Cryptography is meant to protect confidentiality, integrity, authenticity, and non-repudiation. People often mix up encoding, hashing, encryption, and signatures, which leads to a poor mental model. The right mental model is: each primitive solves a different security problem.

### Offensive angle

Attackers look for weak hash algorithms, poor password handling, predictable randomness, and outdated TLS settings. A weak hash or weak password policy is not always exploitable immediately, but it creates a lower-cost path to credential recovery or impersonation.

### Defensive angle

Defenders choose strong password hashing algorithms like Argon2id, bcrypt, or scrypt; enforce MFA where needed; use modern TLS settings; protect secrets in vaults; and avoid storing plaintext credentials. The defense is to make the attacker spend more time and resources than the value of the target.

### Commands explained

- `md5sum`, `sha1sum`, `sha256sum`, `sha512sum`: demonstrate the irreversible digest concept and how small input changes affect the output.
- `john --wordlist=...`: test a lab password hash offline in a controlled environment.
- `openssl enc -aes-256-cbc -salt -pbkdf2`: demonstrate encryption using a modern KDF pattern.
- `openssl rand -hex 32` and `openssl rand -base64 32`: generate random values for tokens and keys.
- `openssl s_client -connect ...`: inspect TLS handshake details such as certificate, protocol, and negotiated cipher.

A strong cryptographic design is not just an algorithm; it is an ecosystem of key management, randomness, verification, and operational controls.

# Read this before touching the lab

Everything in this course is meant for machines you own and a network you deliberately isolated for testing.

Use a Host-Only/Internal network. A simple setup is:

- Kali: `192.168.56.10`
- Target: `192.168.56.20`
- Router: `192.168.56.1`
- Server/DNS/DHCP: `192.168.56.30`

Take VM snapshots before vulnerable configurations.

For attack exercises, replace placeholders such as `<TARGET>` with a lab IP. Do not replace them with a public IP, home router, college network, office network, or someone else's machine.

The point of the lab is not to collect a pile of payloads. For every technique, answer four questions:

1. What is happening on the wire?
2. Why does the target accept it?
3. What evidence would a defender see?
4. What change makes the attack fail?

## Four things people constantly mix up

```text
Encoding      → representation
Hashing       → digest
Encryption    → confidentiality
Signature     → authenticity/integrity
```

Do not call Base64 encryption.

## Hash experiments

```bash
printf 'hello\n' | md5sum
printf 'hello\n' | sha1sum
printf 'hello\n' | sha256sum
printf 'hello\n' | sha512sum
```

Change one character and repeat.

Observe the avalanche effect.

## Password-cracking lab

Create your own small test wordlist:

```bash
cat > ~/lab-wordlist.txt <<'EOF'
password
admin
letmein
summer2026
labpassword123
EOF
```

Create a test hash for a deliberately weak lab password.

With John the Ripper:

```bash
john --wordlist=~/lab-wordlist.txt <YOUR_TEST_HASH_FILE>
john --show <YOUR_TEST_HASH_FILE>
```

Everything here is a hash you created for the lab.

The important lesson is that fast general-purpose hashes are not designed to make password guessing expensive.

Study:

- salts
- Argon2id
- scrypt
- bcrypt
- PBKDF2
- rate limiting
- MFA

## Encryption

Create a file:

```bash
printf 'private lab message\n' > message.txt
```

Encrypt:

```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -in message.txt -out message.enc
```

Decrypt:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in message.enc -out recovered.txt
cat recovered.txt
```

This is a file-encryption demonstration, not a replacement for modern application-level authenticated encryption designs.

## Randomness

```bash
openssl rand -hex 32
openssl rand -base64 32
```

Learn why predictable random values are dangerous for:

- session tokens
- reset tokens
- API keys
- encryption keys
- nonces

## TLS inspection

Against your own HTTPS server:

```bash
openssl s_client -connect <TARGET>:443 -servername lab.test
```

Study:

- certificate
- issuer
- validity
- public key
- negotiated protocol
- cipher
- verification result

## Weak TLS lab

If you have an intentionally old TLS lab server, compare a weak configuration with a hardened one.

Do not deliberately downgrade public services.

## Blue-team exercise

Take a test application and inventory:

```text
Where are passwords stored?
Where are secrets stored?
What hash algorithm?
Is there a salt?
How are sessions generated?
How is TLS configured?
How are keys rotated?
```

Then write a remediation plan.

## Red-team question

If you find an MD5 hash in an application, what exactly does that prove?

It proves a weak algorithm is being used. It does not automatically prove you can recover the password. You still need to understand the input, salt, password quality and cracking cost.
