# ech0raix_decryptor
  
If you are here it means that your NAS has been infected by ech0raix (aka qnap encrypt) and that you 
are either :  
  
- searching for a way to decrypt your files without paying and it might be possible if the ransomware used to encrypt your data is from 2019.  
  Generally 2019 malware creates a text file named **README_FOR_DECRYPT.txt** and some developpers have released a brute force decryptor.
  However if you have been infected by a more recent versions (in this case the text file is **README_FOR_DECRYPT.txtt**) there is no other option than to pay.
  Hope on the futur we will find a way of decoding it.  
    
- You have paid and you have received the decryptor binaries but you don't trust them and you want to execute virus free binary.  
  So welcome on this page and please follow the instruction:
  
  **Step 1)** You first need to extract the key embedded inside the "official" (it's hard to use this word) decryptor_binary.  
              To do so you can download Free version of IDA Disassembler and search inside main_main to find the key as shown below:                 
              ![Alt text](https://github.com/vricosti/ech0raix_decryptor/blob/main/doc/ida_extract_key.png?sanitize=true)

  **Step 2)** Try first to run the decryptor on a folder without deleting the encrypted files.  


