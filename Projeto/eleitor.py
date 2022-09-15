from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import Crypto.Random


class Eleitor:
    def __init__(self):  # Construtor da classe
        self.x=0

    # Assinando a mensagem
    def assina(self, msg):
        key = RSA.import_key(open('files/myPrivatekey.pem').read())
        h = SHA256.new(str(msg).encode("utf-8"))
        signature = pkcs1_15.new(key).sign(h)
        return signature

    def verifySignature(self, msg, signature):
        key = RSA.import_key(open('files/myPublicKey.pem').read())
        h = SHA256.new(str(msg).encode("utf-8"))

        try:
            pkcs1_15.new(key).verify(h, signature)
            print("Assinatura da passagem do VN da CLA-Eleitor Válida.")
            return 1
        except (ValueError, TypeError):
            print("Assinatura da passagem do VN da CLA-Eleitor Inválida.")
            exit()

    def mensage(self, vn, voto, id):
        aux = ' '  # serve para aplicar o split()
        msg = str(vn + aux + voto + aux + id)
        return msg

    def encriptaMSG(self, msg):

        # Gerando arquivo que será encriptado
        file = open("files/Encrypted_MSG.bin", 'wb')

        # print para conferir posteriormente
        # print("Mensagem incial........:", msg)

        # Importando a chave pública do RSA
        public = RSA.import_key(open("files/myPublicKey.pem").read())
        # Gerando a chave do AES
        AES_key = Crypto.Random.get_random_bytes(16)
        # Encriptando o AES_key com a chave pública do RSA.
        cipher_rsa = PKCS1_OAEP.new(public)
        enc_AES_key = cipher_rsa.encrypt(AES_key)

        # Encriptando a informação a ser passada com AES.
        cipher_aes = AES.new(AES_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode("utf-8"))

        [file.write(x)
         for x in (enc_AES_key, cipher_aes.nonce, tag, ciphertext)]
        file.close()

        return ciphertext

    def DecriptaVN(self, ciphertext):

        file = open("files/Encrypted_Validation_Number.bin", "rb")
        public_key = RSA.import_key(
            open("files/myPublicKey.pem").read())

        enc_AES_key, nonce, tag, ciphertext = \
            [file.read(i) for i in (public_key.size_in_bytes(), 16, 16, -1)]

        # Importando a chave privada do RSA
        privada = RSA.import_key(open("files/myPrivateKey.pem").read())

        # Decriptando o en_AES_key com a chave privada do RSA.
        cipher_rsa = PKCS1_OAEP.new(privada)
        AES_key = cipher_rsa.decrypt(enc_AES_key)

        # Decriptando data com AES_key.
        cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)


        # Gera o arquivo com VN decriptado.
        new_file = open("files/Decrypted_Validation_Number.txt", "a")
        new_file.write(str(data))
        new_file.write('\n')
        new_file.close()
        file.close()

        return data
