import sys
import os
from Crypto.Cipher import AES
from Crypto import Random

def decrypt(key, ciphered_filepath):
    with open(ciphered_filepath,"rb") as f:
        content = f.read()
        if len(content) > 16:
            iv = content[0:16]
            cyphertext = content[16:]
            cipher = AES.new(key, AES.MODE_CFB, iv)
            plaintext = cipher.decrypt(cyphertext)




def main():
    cur_path = os.path.dirname(os.path.realpath(__file__))

    key = "4STDs9cmUlkiujXuLkdTouoqOIfER4TE"


    for dirpath, subdirs, files in os.walk(cur_path):
         for file in files:
             if file.endswith('.encrypt'):
                 decrypt(key, os.path.join(dirpath, file))


if __name__ == "__main__":
    main()
