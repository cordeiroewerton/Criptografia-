import string
import random

carac = string.ascii_lowercase

key = random.sample(string.ascii_lowercase, len(string.ascii_lowercase))

txt = input("DIGITE O TEXTO CLARO:")
new_txt=""

for i in txt:
    new_letter = key[carac.find(i)]
    new_txt += new_letter

print(new_txt)

print("-----------------------------------------")

new_new_txt = ""

for j in new_txt:
    new_letter = carac[key.index(j)]
    new_new_txt += new_letter

print(new_new_txt)

print("-----------------------------------------")

print(key)