from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA key pair (private and public keys)
key = RSA.generate(2048)

# Extract the private and public keys
private_key = key
public_key = key.publickey()

# Create a cipher object using the public key
cipher_rsa = PKCS1_OAEP.new(public_key)

# Encrypt your name using the public key
plaintext = 'Shilphy P. Gonsalvez'.encode('utf-8')
ciphertext = cipher_rsa.encrypt(plaintext)

# Print encrypted name (ciphertext)
print(f'RSA Encrypted: {ciphertext.hex()}')

# Decrypt the ciphertext using the private key
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)
decrypted_text = cipher_rsa_decrypt.decrypt(ciphertext).decode('utf-8')

# Print decrypted name
print(f'RSA Decrypted: {decrypted_text}')
