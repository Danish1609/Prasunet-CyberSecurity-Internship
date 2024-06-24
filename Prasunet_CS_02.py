from PIL import Image
import numpy as np

def load_image(image_path):
    """Load an image and convert it to a numpy array."""
    image = Image.open(image_path)
    image = image.convert('RGB')  
    return np.array(image)

def save_image(image_array, output_path):
    """Save a numpy array as an image."""
    image = Image.fromarray(image_array)
    image.save(output_path)
    

def generate_key(image_shape, seed):
    """Generate a random key based on the image shape and a seed."""
    np.random.seed(seed)
    key = np.random.randint(0, 256, size=image_shape, dtype=np.uint8)
    return key


def encrypt_image(image_array, key):
    """Encrypt the image using XOR with the key."""
    encrypted_image = np.bitwise_xor(image_array, key)
    return encrypted_image


def decrypt_image(encrypted_image, key):
    """Decrypt the image using XOR with the key."""
    decrypted_image = np.bitwise_xor(encrypted_image, key)
    return decrypted_image



input_image_path = "C:/Users/danis/OneDrive/Desktop/Prasunet/Prasunet_CS_02/input.webp"
output_encrypted_path = "C:/Users/danis/OneDrive/Desktop/Prasunet/Prasunet_CS_02/encrypt.webp"
output_decrypted_path = "C:/Users/danis/OneDrive/Desktop/Prasunet/Prasunet_CS_02/decrypt.webp"

# Load the image
image_array = load_image(input_image_path)


# Generate a key
seed = 12345  # Seed for random key generation
key = generate_key(image_array.shape, seed)


# Encrypt the image
encrypted_image = encrypt_image(image_array, key)
save_image(encrypted_image, output_encrypted_path)


# Decrypt the image
decrypted_image = decrypt_image(encrypted_image, key)
save_image(decrypted_image, output_decrypted_path)

print("\n Encryption and decryption completed !! \n")