import string
import random

def mod26(x):
    y = int(x/26)
    j = y*26
    return x-j


def cesar(txt, key, carac):
    convertido = ""
    # for para verificar toda o texto
    for i in txt:
        if i in carac:
            num = carac.find(i)
            num += key
        # ifs para caso a chave seja menor que 0 e maior que a cadeira de caracteres presentes
        if num >= len(carac):
            num = num - len(carac)
        elif num < 0:
            num = num + len(carac)
        convertido += carac[num]
    return convertido


#definindo os caracteres e textos

x=int(input("AAA:"))
y=mod26(x)
print(y)

carac = string.ascii_letters + string.punctuation
texto = input("DIGITE O TEXTO CLARO:")
chave = [random.randint(0,25) for i in range(0,len(texto))]
convertido = cesar(texto,chave,carac)
print(convertido)

