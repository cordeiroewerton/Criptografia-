from CLA import *
from eleitor import *
from CTF import *

# Criação dos objetos
cla = CLA()
eleitor = Eleitor()
ctf = CTF()


# ------------------ CLA    -Eleitor -------------------

print("--------------------- BEM VINDO(A) ---------------------")


ID = str(input("DIGITE O ID: "))
assign = eleitor.assina(ID)

if cla.verifySignature(ID, assign):
    if cla.verificaMSG(ID):
        cla.AddID(ID)
        vn = cla.returnVN()
        assign_vn = cla.makeSignature(vn)
        # enviando o VN assinado para o CTF

        if eleitor.verifySignature(vn, assign_vn):

            Decry_vn = eleitor.DecriptaVN(vn)  # Retorna <class 'bytes'>
            voto = str(input("13 || 17: "))  # Retorna <class 'str'>

            # ---------------- Eleitor-CTF -----------------
            msg = eleitor.mensage(str(Decry_vn), voto, ID)
            assign_msg = eleitor.assina(msg)

            if ctf.verifySignature(msg, assign_msg):
                enc_msg = eleitor.encriptaMSG(msg)
                decri_msg = ctf.decriptaMSG(enc_msg)

                # Separando a mensagem do eleitor
                vet_msg = []
                vet_msg = decri_msg.split()
                VN, Voto, ID = vet_msg[0], vet_msg[1], vet_msg[2]
                # ---------------- CTF ---------------------
                if ctf.verificaLista(VN) == 0:
                    ctf.addLista(VN)
                    ctf.addVoto(Voto, ID)
                    ctf.contagemDeVotos()
                    ctf.imprimirVotos()
                else:
                    print("Fechando o programa")
            else:
                print("Fechando o programa")
        else:
            print("Fechando o programa")
    else:
        print("Fechando o programa")
else:
    print("Fechando o programa")
