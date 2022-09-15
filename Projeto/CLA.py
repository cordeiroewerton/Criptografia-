from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
import Crypto.Random


class CLA:
    def __init__(self):
        """Construtor"""


    def hashGenarator(msg):
        hash = SHA256.new()  # retorna um SHA256Hash object
        hash.update(str.encode(msg))
        return hash.hexdigest()

    # verificando linha por linha se o VN é repetido
    def verifica(self, l):
        id1 = open('files/Validation-Number.txt', 'r')
        for linha in id1:  # verificando linha por linha se o usuario já está cadastrado
            linha = linha.rstrip()
            if (l == linha):
                return 1
            else:
                return 0

    def verificaMSG(self,id):
        id1 = open('files/ID_number.txt', 'r')
        for linha in id1:  # verificando linha por linha se o usuario já está cadastrado
            linha = linha.rstrip()
            if (id == linha):
                print("ID já existente")
                return False
                break
        return True


    def AddID(self,id):
        with open("files/ID_number.txt", 'a') as f1:
            f1.write(id)
            f1.write("\n")
            f1.close()

    # Gera um par de chaves publica/privada
    def generateKeys(self):

        private_key = RSA.generate(1024, Crypto.Random.new().read)
        public_key = private_key.public_key()

        private_key = private_key.exportKey()
        public_key = public_key.exportKey()

        with open("files/myPrivateKey.pem", "wb") as f:
            f.write(private_key)
            f.close()

        with open("files/myPublicKey.pem", "wb") as f:
            f.write(public_key)
            f.close()

    # Assinando a mensagem
    def makeSignature(self, msg):
        key = RSA.import_key(open('files/myPrivatekey.pem').read())
        h = SHA256.new(str(msg).encode("utf-8"))
        signature = pkcs1_15.new(key).sign(h)
        return signature





    # Verificando se a assinatura é valida
    def verifySignature(self, msg, signature):

        key = RSA.import_key(open('files/myPublicKey.pem').read())
        h = SHA256.new(str.encode(msg))

        try:
            pkcs1_15.new(key).verify(h, signature)
            print("Assinatura do pedido de VN Eleitor-CLA Válida.")
            return 1
        except (ValueError, TypeError):
            print("Assinatura do pedido de VN Eleitor-CLA Inválida.")
            exit()

    # retornando VN

    def returnVN(self):

        # Recebendo os valores do arquivo
        data = Crypto.Random.get_random_bytes(16)  # VN
        # print("Data no returnVN().........:", data)

        # Gerando arquivo que será encriptado
        file = open("files/Encrypted_Validation_Number.bin", 'wb')

        # Importando a chave pública do RSA
        public = RSA.import_key(open("files/myPublicKey.pem").read())
        # Gerando a chave do AES
        AES_key = Crypto.Random.get_random_bytes(16)
        # Encriptando o AES_key com a chave pública do RSA.
        cipher_rsa = PKCS1_OAEP.new(public)
        enc_AES_key = cipher_rsa.encrypt(AES_key)

        # Encriptando a informação a ser passada com AES.
        cipher_aes = AES.new(AES_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        [file.write(x)
         for x in (enc_AES_key, cipher_aes.nonce, tag, ciphertext)]
        file.close()

        # print("Texto cifrado pelo AES.....:", ciphertext)
        return ciphertext
