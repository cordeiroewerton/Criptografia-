from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import Crypto.Random


class CTF:
    def __init__(self):
        self.votoA = 0
        self.votoB = 0

    def verifySignature(self, msg, signature):
        key = RSA.import_key(open('files/myPublicKey.pem').read())
        h = SHA256.new(str.encode(msg))

        try:
            pkcs1_15.new(key).verify(h, signature)
            print("Assinatura da mensagem Eleitor-CTF Válida.")
            return 1
        except (ValueError, TypeError):
            print("Assinatura da mensagem Eleitor-CTF Inválida.")
            exit()

    # adiciona os votos em dois arquivos diferentes
    def addVoto(self, voto, ID):

        if (voto == "13"):
            with open("files/voto_a.txt", "a") as f1:
                aux1 = voto + " " + ID
                f1.write(aux1)
                f1.write("\n")
                f1.close()
        elif (voto == "17"):
            with open("files/voto_b.txt", "a") as f2:
                aux1 = voto + " " + ID
                f2.write(aux1)
                f2.write("\n")
                f2.close()
        else:
            print("CANDIDATO NÃO ENCONTRADO")

    # conta todos os votos
    def contagemDeVotos(self):
        id1 = open("files/voto_a.txt")
        id2 = open("files/voto_b.txt")
        for linha in id1:
            linha = linha.rstrip()
            l1 = linha.split()
            laux1 = l1[0]
            if (laux1 == "13"):
                self.votoA = self.votoA + 1
        for linha in id2:
            linha = linha.rstrip()
            l2 = linha.split()
            laux2 = l2[0]
            if (laux2 == "17"):
                self.votoB = self.votoB + 1
        return self.votoA, self.votoB

    def imprimirVotos(self):
        id1 = open("files/voto_a.txt")
        id2 = open("files/voto_b.txt")
        for linha in id1:
            linha = linha.rstrip()
            print(linha)
        self.votoA += 1

        for linha in id2:
            linha = linha.rstrip()
            print(linha)
        self.votoB += 1

        print("QUANTIDADE DE VOTOS PARA O CANDITATO 13:", self.votoA-1)
        print("QUANTIDADE DE VOTOS PARA O CANDITATO 17:", self.votoB-1)

    def addLista(self, D_vn):
        with open("files/Decrypted_Validation_Number_CTF.txt", 'a') as f1:
            f1.write(D_vn)
            f1.write("\n")
            f1.close()

    def verificaLista(self, ele_VN):
        id1 = open('files/Decrypted_Validation_Number_CTF.txt', 'r')
        for linha in id1:  # verificando linha por linha se o usuario já está cadastrado
            linha = linha.rstrip()
            if (ele_VN == linha):
                return 1
            else:
                return 0

    # Decripta mensagem vinda do eleitor.
    def decriptaMSG(self, ciphertext):

        file = open("files/Encrypted_MSG.bin", "rb")
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
        msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # teste
        # print("Mensagem decriptada:", msg)

        # Gera o arquivo com VN decriptado.
        new_file = open("files/Decrypted_MSG.txt", "a")
        new_file.write(str(msg))
        new_file.write('\n')
        new_file.close()
        file.close()

        return str(msg)

# afdas
