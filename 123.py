import random
import string

def generate_nonce(length=7):
    characters = string.ascii_letters + string.digits
    nonce = ''.join(random.choice(characters) for _ in range(length))
    return nonce

# Example usage
nonce_example1 = generate_nonce()
nonce_example2 = generate_nonce(8)

print(nonce_example1)
print(nonce_example2)
