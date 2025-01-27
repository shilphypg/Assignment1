import hashlib

# Your name
name = 'Shilphy P. Gonsalvez'

# Generate SHA256 hash
sha256_hash = hashlib.sha256(name.encode('utf-8')).hexdigest()

# Print the hash
print(f'SHA256 Hash: {sha256_hash}')
