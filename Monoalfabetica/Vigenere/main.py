import string
from random import randint

letters = string.ascii_letters + string.punctuation

texto = "Hello"
chave = [randint(1, 25) for i in range(0, len(texto))]

print("Texto Claro: ", texto)

# Encripta
def vigenere(txt, key):
    convertido = ""

    for j, i in enumerate(txt, start=0):
        if i in letters:
            num = letters.find(i)
            num += key[j]
            convertido += letters[num]
    return convertido


print("Encriptação por Vigenère: ", vigenere(texto, chave))

# Decripta
def D_vigenere(txt, key):
    convertido = ""

    for j, i in enumerate(txt, start=0):
        if i in letters:
            num = letters.find(i)
            num -= key[j]
            convertido += letters[num]
    return convertido


print("Vigenère Decriptada: ", D_vigenere(vigenere(texto, chave), chave))
print("Chave: ", chave)

