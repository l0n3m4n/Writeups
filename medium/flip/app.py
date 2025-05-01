

```py
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
``