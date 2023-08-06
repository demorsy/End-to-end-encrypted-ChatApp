from Crypto.PublicKey import RSA
#STEP 1 -----------------------------------------------------------------
def generate_keys_RSA():
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


a_RSAprivate, a_RSApublic = generate_keys_RSA()
b_RSAprivate, b_RSApublic = generate_keys_RSA()

print(a_RSApublic)
print("\n\n\n\n")
print(a_RSAprivate)


#STEP 2 -----------------------------------------------------------------

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def symmetric_key_encryption_decryption(private_key, public_key):
    # 256 bit simetrik anahtar oluşturma
    symmetric_key = PBKDF2("password", "salt", dkLen=32)
    
    # Simetrik anahtarı genel anahtarla şifreleme
    rsa_public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)

    # Simetrik anahtarı özel anahtarla deşifreleme
    rsa_private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)

    return symmetric_key, encrypted_key, decrypted_key


print("\n\n\n\n")
symmetric_key, encrypted_key, decrypted_key = symmetric_key_encryption_decryption(a_RSAprivate, a_RSApublic)
print("Ks(Symmetric Key): --> ", symmetric_key)
print("\n\n")
print("Ka+(Ks): --> ", encrypted_key)
print("\n\n")
print("Ka-(Ka+(Ks)): --> ", decrypted_key)
print("\n")

#STEP 3 -----------------------------------------------------------------
print("----------------- step 3 -----------------\n")
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC

def digital_signature(private_key, message):
    # Mesajı özetleme (hash)
    hashed_message = SHA256.new(message.encode())

    # Dijital imza oluşturma
    rsa_private_key = RSA.import_key(private_key)
    signature = pkcs1_15.new(rsa_private_key).sign(hashed_message)
    return hashed_message, signature

def verification(public_key, hashed_message, signature):
    # Dijital imzayı doğrulama
    rsa_public_key = RSA.import_key(public_key)
    try:
        pkcs1_15.new(rsa_public_key).verify(hashed_message, signature)
        verification = True
    except (ValueError, TypeError):
        verification = False

    return verification

text = "Merhaba! Selam dostum! Ağaç kelimesi eski çağlardan beri dilimizde yaşamaktadır. Orhun Yazıtları’nda bile ağaçla karşılaşırız. "
print("Message: --> " , text)
print("\n")
hashed_message, signatured = digital_signature(a_RSAprivate, text)
verif = verification(a_RSApublic, hashed_message, signatured)
print("Hashed Message -->" ,  hashed_message.hexdigest())
print("\n")
print("Signature --> " , signatured)
print("\n")
print("Verification result: -> " ,verif)

#STEP 4 -----------------------------------------------------------------
print("----------------- step 4 -----------------\n")
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encryption_decryption(symmetric_key, message):
    # Rastgele bir IV oluşturma
    iv = get_random_bytes(16)

    # Mesajı şifreleme
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(message.encode().ljust(16))

    # Şifrelenmiş metni deşifreleme
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext).decode().rstrip()

    return ciphertext, decrypted_message

text = "Merhaba! Selam dostum! Ağaç kelimesi eski çağlardan beri dilimizde yaşamaktadır. Orhun Yazıtları’nda bile ağaçla karşılaşırız. "
chiphertext, plainttext_decrypted = aes_encryption_decryption(symmetric_key,text)
print("Message: " , text)
print("\n")
print("Chipher Text: " , chiphertext)
print("\n")
print("Plain Text(decrytped) ",plainttext_decrypted)
print("\n")
print("Different IV part ----->")
chiphertext2, plainttext_decrypted2 = aes_encryption_decryption(symmetric_key,text)
print("Chipher Text (with First IV): " , chiphertext)
print("\n")
print("Chipher Text (with Second IV): " , chiphertext2)
print("\n")
print("They are same plaint text.")
print("\n")
print("Plain Text(decrytped) ",plainttext_decrypted2)
print("\n")


#STEP 5 -----------------------------------------------------------------
print("----------------- step 5 -----------------\n")
def new_key_from_hmac(symmetric_key):
    hmac = HMAC.new(symmetric_key, digestmod=SHA256)
    new_key = hmac.digest()
    return new_key, hmac


#part a
hmac_key, hmac = new_key_from_hmac(symmetric_key)
print("HMAC", hmac.hexdigest())

#part b
new_key, _ = new_key_from_hmac(hmac_key)
print("New Key", new_key)