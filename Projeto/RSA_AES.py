from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
import Crypto.Random


def returnVN():

    # Recebendo os valores do arquivo
    data = Crypto.Random.get_random_bytes(16)  # VN
    # Gerando arquivo que será encriptado
    file = open("Projeto/files/Encrypted_Validation_Number.bin", 'wb')

    # print para conferir posteriormente
    print("Data no returnVN().........:", data)

    # Importando a chave pública do RSA
    public = RSA.import_key(open("Projeto/files/myPublicKey.pem").read())
    # Gerando a chave do AES
    AES_key = Crypto.Random.get_random_bytes(16)
    # Encriptando o AES_key com a chave pública do RSA.
    cipher_rsa = PKCS1_OAEP.new(public)
    enc_AES_key = cipher_rsa.encrypt(AES_key)

    # Encriptando a informação a ser passada com AES.
    cipher_aes = AES.new(AES_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    [file.write(x) for x in (enc_AES_key, cipher_aes.nonce, tag, ciphertext)]
    file.close()

    print("Texto cifrado pelo AES.....:", ciphertext)
    return ciphertext


def DecriptaVN(ciphertext):

    file = open("Projeto/files/Encrypted_Validation_Number.bin", "rb")
    public_key = RSA.import_key(
        open("Projeto/files/myPublicKey.pem").read())

    enc_AES_key, nonce, tag, ciphertext = \
        [file.read(i) for i in (public_key.size_in_bytes(), 16, 16, -1)]

    # Importando a chave privada do RSA
    privada = RSA.import_key(
        open("Projeto/files/myPrivateKey.pem").read())

    # Decriptando o en_AES_key com a chave privada do RSA.
    cipher_rsa = PKCS1_OAEP.new(privada)
    AES_key = cipher_rsa.decrypt(enc_AES_key)

    # Decriptando data com AES_key.
    cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # teste
    print("Data ao fim do DecriptaVN():", data)

    # Gera o arquivo com VN decriptado.
    new_file = open("Projeto/files/Decrypted_Validation_Number.txt", "a")
    new_file.write(str(data))
    new_file.write('\n')
    new_file.close()
    file.close()


cyphertext = returnVN()
DecriptaVN(cyphertext)
