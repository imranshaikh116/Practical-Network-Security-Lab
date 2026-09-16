# 10 Command Notebook — Cryptography: Hashing, Randomness, Encryption, and TLS

This module is about understanding what cryptographic primitives actually do. The offensive angle is to look for weak hashes, weak password handling, bad random generation, and improper TLS configuration. The defensive angle is to choose strong algorithms, protect secrets, and verify that keys and certificates are properly managed.

## 1) Hash demonstration

```bash
printf 'hello\n' | md5sum
printf 'hello\n' | sha1sum
printf 'hello\n' | sha256sum
printf 'hello\n' | sha512sum
```

### Offensive purpose
- Shows how different hashing algorithms produce fixed-size digests from input data.
- Useful for understanding the difference between fast general-purpose hashes and password hashing functions.

### Defensive purpose
- A defender can identify weak passwords or insecure hash usage in an application, especially when older algorithms are still used.

### Important point
- Hashing is not encryption.
- Hashes are useful for integrity and password storage, but they do not provide confidentiality.

---

## 2) Random values and key material

```bash
openssl rand -hex 32
openssl rand -base64 32
```

### Offensive purpose
- Generates randomness for tokens, keys, and salts.
- Attackers study whether a system uses adequate randomness because predictability can lead to session forgery or password recovery.

### Defensive purpose
- Strong randomness is a requirement for secure keys, nonces, and session IDs.
- A defender should verify that generated values are not predictable or reused.

---

## 3) File encryption demo

```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -in message.txt -out message.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in message.enc -out recovered.txt
```

### Offensive purpose
- Demonstrates symmetric encryption and basic key handling in a lab environment.
- Useful for understanding the role of salting and password-based key derivation.

### Defensive purpose
- Helps explain why modern applications use hardened key derivation and authenticated encryption instead of ad hoc file encryption.

---

## 4) Password cracking on a controlled lab hash

```bash
john --wordlist=~/lab-wordlist.txt <YOUR_TEST_HASH_FILE>
john --show <YOUR_TEST_HASH_FILE>
```

### Offensive purpose
- Shows how a weak password can be recovered if the password hash is weak and the password is in a small wordlist.
- Demonstrates why password hashing algorithms must be computationally expensive.

### Defensive purpose
- Blue teams validate that password storage uses strong hashing and salting, not plain MD5 or unsalted SHA-1.
- This is where Argon2id, bcrypt, scrypt, and PBKDF2 matter.

---

## 5) TLS inspection

```bash
openssl s_client -connect <TARGET>:443 -servername lab.test
```

### Offensive purpose
- Reveals the certificate chain, issuer, protocol, ciphers, and TLS negotiation behavior.
- Useful for testing whether an HTTPS endpoint is weak, outdated, or misconfigured.

### Defensive purpose
- Confirms that the service is offering secure, current TLS settings and a valid certificate.
- Helps detect expired, self-signed, weak-cipher, or outdated-protocol services.

---

## Key lesson
- Weak hashing and weak random generation are not “small issues”; they can become credential compromise or impersonation paths.
- Proper cryptography is about selecting the right primitive for the right job and managing it safely.
