from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# 1. Base64 Encoding and Decoding
name = 'Shilphy P. Gonsalvez'
encoded_name = base64.b64encode(name.encode('utf-8')).decode('utf-8')
print(f'Base64 Encoded: {encoded_name}')
decoded_name = base64.b64decode(encoded_name).decode('utf-8')
print(f'Decoded Name: {decoded_name}')

# 2. AES Encryption and Decryption
key = 'hackerspace12345'.encode('utf-8')  # 16-byte key
plaintext = name.encode('utf-8')

# Encrypt
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
print(f'AES Encrypted: {ciphertext.hex()}')

# Decrypt
decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
print(f'AES Decrypted: {decrypted_text}')

# 3. RSA Key Pair Generation
key = RSA.generate(2048)

# Extract the private and public keys
private_key = key
public_key = key.publickey()

# Create a cipher object using the public key
cipher_rsa = PKCS1_OAEP.new(public_key)

# Encrypt your name using the public key
ciphertext_rsa = cipher_rsa.encrypt(plaintext)
print(f'RSA Encrypted: {ciphertext_rsa.hex()}')

# Decrypt the ciphertext using the private key
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)
decrypted_text_rsa = cipher_rsa_decrypt.decrypt(ciphertext_rsa).decode('utf-8')
print(f'RSA Decrypted: {decrypted_text_rsa}')

# 4. SHA256 Hashing and Attempt to Reverse
hash_object = hashlib.sha256(name.encode('utf-8'))
sha256_hash = hash_object.hexdigest()
print(f'SHA256 Hash: {sha256_hash}')
