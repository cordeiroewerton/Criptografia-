
#definindo os caracteres e textos
carac = "abcdefghijklmnopqrstuvwyzàáãâéêóôõíúçABCDEFGHIJKLMNOPQRSTUVWYZÀÁÃÂÉÊÓÕÍÚÇ "
texto = input("DIGITE O TEXTO CLARO:")
chave = int(input("DIGITE A CHAVE:"))
modo = input("ESCOLHE UM MODO PARA O PROGRAMA (E-ENCRIPTAR/D-DECRIPTAR):")
convertido = ''

#for para verificar toda o texto
for caracter in texto:
#decripitando ou encriptando os textos
    if caracter in carac:
        num = carac.find(caracter)
        if modo == 'E' or modo == 'e':
            num = num + chave
        elif modo == 'D' or modo == 'd':
            num = num - chave
#ifs para caso a chave seja menor que 0 e maior que a cadeira de caracteres presentes
    if num >= len(carac):
        num = num - len(carac)
    elif num < 0:
        num = num + len(carac)

    convertido += carac[num]

#printando os textos
if modo == 'E' or modo == 'e':
    print("O TEXTO CIFRADO É: ", convertido)
if modo == 'D' or modo == 'd':
    print("O CODIGO DECRIPTADO É:", convertido)