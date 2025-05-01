![flip](Intro.png)

![download](2025-05-01_01-20.png)

# Real-World Scenario: Bit-Flipping Attack on CBC Mode

Let’s consider an authenticated encryption vulnerability in a system using CBC mode without integrity protection (e.g., no HMAC or message authentication code). An attacker can exploit this by flipping bits in the ciphertext, which will result in specific changes to the plaintext when decrypted.
## Scenario:

Imagine a web application that uses encryption to protect user login information (username and password). If the application is vulnerable to a bit-flipping attack, an attacker might intercept the encrypted data (e.g., the ciphertext) and modify it.

For example, consider the following:

- The user’s decrypted data (plaintext) :
```sql
-- Create pgcrypto extension and users table
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE users (id SERIAL PRIMARY KEY, username TEXT, password BYTEA);

-- Insert a user with encrypted password
INSERT INTO users (username, password)
VALUES ('johndoe', crypt('mySecretPassword', gen_salt('bf')));

-- Verify login (check password)
SELECT username FROM users WHERE username = 'johndoe' AND crypt('mySecretPassword', password) = password;

```
- Where the first part (IV) is the Initialization Vector (typically 16 bytes), and the second part is the ciphertext corresponding to the actual user data (username and password, for example).

    An attacker wants to change the username, without knowing the password (because the attacker can’t decrypt it directly, but knows the structure of the data). In CBC mode, a flipped bit in a ciphertext block can modify the plaintext in a predictable manner.

## Attack Steps:

- Intercept the Ciphertext: The attacker intercepts the ciphertext sent between the client and server. This ciphertext includes an IV (Initialization Vector) and encrypted user data (e.g., username and password).
- Flip Bits: The attacker flips a bit in the ciphertext block containing the username. Let’s say the attacker flips the first byte. This will cause the decryption process to modify only a specific part of the decrypted plaintext (e.g., the username), and the rest will remain intact.
- Observe the Decryption Behavior: The attacker sends the modified ciphertext to the server, where it gets decrypted. The server’s decryption process will produce a modified plaintext, where the flipped bit alters the username.
- Controlled Modification: The attacker may not know exactly what the plaintext looks like (e.g., the username), but flipping certain bits systematically can cause the plaintext to have a predictable change. For example, flipping the byte that represents a specific character in the username could change "Alice" to "Alisc" or "Alicd".

## Flipping bit exploit

```pgsql
from binascii import unhexlify, hexlify

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Original ciphertext (starts with IV = first 16 bytes)
original_ct_hex = "2967bbf26f408ab8a2d27ad55f97b846f51fd2093970f1011789f346877cfb34515c382c7717570b74d6885c3d545c49" # replace 
ct_bytes = unhexlify(original_ct_hex)

# Split into IV (C0) and rest
C0 = ct_bytes[:16]
rest = ct_bytes[16:]

# Flip 'a' → 'b' in first byte (0x61 → 0x62 = xor 0x03)
# Flip 'd' → 'd' (no change = xor 0x00)
delta = bytes([0x03, 0x00] + [0x00] * 14)

# Apply flip to C0
C0_flipped = xor_bytes(C0, delta)

# Rebuild final ciphertext
forged_ct = C0_flipped + rest

# Output the result
print("🔐 Forged Ciphertext (flip first 2 chars):")
print(forged_ct.hex())
```
### What this code does:

This code is manipulating some encrypted data (called ciphertext). Encryption is a way of turning data into a secret code so no one can read it without the correct key. The ciphertext is essentially the "encrypted" version of the original message.

Here’s what’s happening step by step:

#### Ciphertext and IV:

- The original ciphertext is a long string of numbers/letters (in hexadecimal format).
- The first 16 bytes of the ciphertext are called the **IV (Initialization Vector)**. This is like a random starting point used in encryption.
- The rest of the ciphertext (after the first 16 bytes) contains the actual encrypted data.

#### Flipping some bits:

- In cryptography, a small change in the data can completely change the result. The code is flipping the first byte of the **IV** (the first 16 bytes of the ciphertext).
- The "flip" means changing a character from one value to another, and this is done by XOR (a kind of mathematical operation) between the original and the changed values.
- For example, changing the letter `'a'` (hex value `0x61`) to `'b'` (hex value `0x62`) is done by XOR-ing with `0x03` (which is the difference between `0x61` and `0x62`).

#### Creating a new (forged) ciphertext:

- After flipping the first byte, it then rebuilds the ciphertext by combining the new flipped part (the new IV) with the rest of the encrypted data.
- This creates a new **forged ciphertext**, which might look like a valid encryption but is actually altered.

### Why do this?

This kind of manipulation might be useful in some **attacks** or for testing how an encryption system handles small changes in the data. The main point here is that small changes (like flipping a bit) can result in big changes in the encrypted result, and this is a behavior that is sometimes useful in security research or attacking weak encryption systems.

### Summary:

- You're starting with some encrypted data.
- You're flipping the first byte of the encryption key (IV) in a controlled way.
- Then, you're creating a new version of the encrypted data with this changed starting point.

It’s like taking a "secret message", changing just the first part, and seeing how that affects the whole message when decrypted.

---

### Type of Attack: Bit Flipping Attack

#### What is a Bit-Flipping Attack?

A **bit-flipping attack** occurs when an attacker alters the individual bits or bytes of encrypted data (ciphertext) to change the decrypted result in a predictable manner. In this case, you're flipping the bits of the **Initialization Vector (IV)** to modify the decrypted plaintext after it is processed by the decryption algorithm.

This attack takes advantage of how sensitive encryption systems are to small changes in the input. Flipping even one bit in the ciphertext can lead to a completely different decrypted message.

In the provided code, the attacker is flipping a byte in the IV, and this is done using XOR operations, which are simple but powerful methods for making predictable alterations to encrypted data.

---

### Simple Example of a Bit-Flipping Attack

1. **Original Message**:  
   You want to encrypt the message "HELLO".

   After encryption, the ciphertext might look like this (this is a **random example**):

```plaintext
Ciphertext:  1101011100110111
```
2. **Encryption Process**:
The encryption system uses an IV and an encryption key to turn the message into this ciphertext. The IV might look like:
```
IV: 1100000000000000
```

3. **Attacker Flips a Bit**:
An attacker decides to flip the first bit of the IV. So, instead of 1100000000000000, the IV becomes:
```
IV after flip: 0100000000000000
```

4. **What happens after flipping**?
The attacker doesn't know the key or the message, but by flipping that first bit of the IV, the ciphertext will change completely.

After the flip, the decryption will give an entirely different result. In this case, the decrypted message could be something like:
```
    Decrypted message: "?????"
```
The message is now corrupted, and the attacker might not have learned the original message. But in some cases, this change can lead to predictable outcomes when the encryption system is weak or doesn't properly check the changes.
    
