YOU ARE USING THIS TOOL AT YOUR OWN RISK.

-----------------------------------------------------------------------------------------------------------
Before you start to read this readme, please check if you have the latest version of ECh0raixDecoder package.
http://download.bleepingcomputer.com/BloodDolly/ECh0raixDecoder.zip

If you have any question you can contact me here:
http://www.bleepingcomputer.com/forums/index.php?app=members&module=messaging&section=send&do=form&fromMemberID=950574
-----------------------------------------------------------------------------------------------------------

1. Introduction
2. Quick guide
 2.1 Decryption (Known key)
 2.2 Decryption (Unknown key)
3. Listing encrypted files
4. Adding keys
 4.1 Add keys
 4.2 From ransom note
 4.3 From file
5. Recovering decryption key
 5.1 Pair of encrypted and original file
 5.2 Two encrypted files
 5.2 Exhaustive search
 5.4 Number of threads

===============
1. Introduction
===============
ECh0raix Decoder is a tool for decryption of files encrypted by ECh0raix ransomware.

==============
2. Quick guide
==============

2.1 Decryption (Known keys)
===========================
I do recommend to backup all the encrypted files before using this tool.

1. Run ECh0raixDecoder.exe as administrator (needed for hidden/system/personal folders)
2. Click on Add keys button
3. Copy/paste the key for your files (read section 4)
4. Click on Add keys button
5. You can decrypt your files using one of the following features:
 5a. Decrypt Folder - It will decrypt encrypted files in selected folder (I recommend to use this option to test decryption)
 5b. Decrypt All - It will search encrypted files on all FIXED and REMOTE drives and try to decrypt them
 5c. Decrypt List - It will decrypt encrypted files listed in selected list file (read section 3)
6. See log for more information (path to log file will be shown in the dialog)

In the case of failure or error please contact me.


2.2 Decryption (Unknown keys)
=============================
I do recommend to backup all the encrypted files before using this tool.

1. Run ECh0raixDecoder.exe as administrator (needed for hidden/system/personal folders)
2. Click on Find key button
3. Select the pair of encrypted and unecnrytped version of the same file or two encrypted files or folder with encrypted files (read section 5)
4. If the key is found it is automatically added to the pool of keys
5. You can decrypt your files using one of the following features:
 5a. Decrypt Folder - It will decrypt encrypted files in selected folder (I recommend to use this option to test decryption)
 5b. Decrypt All - It will search encrypted files on all FIXED and REMOTE drives and try to decrypt them
 5c. Decrypt List - It will decrypt encrypted files listed in selected list file (read section 3)
6. See log for more information (path to log file will be shown in the dialog)

In the case of failure or error please contact me.

==========================
3. Listing encrypted files
==========================
ECh0raix Decoder can search for encrypted files and create a list of found files. Single folder or all drives can be selected and then examined. When listing is performed, ECh0raix Decoder will check all files in the selected folder or on all mapped drives and try to find encrypted files by ECh0raix ransomware.

When the list file is created it can be used for decryption as a source of paths for decryption process.
The path can points to a single file or a folder. When target location is a folder and the list file is used for decryption all files in that folder are decrypted if possible.

Any unicode txt file with full paths on each line can be used as a list file.


Example:
C:\Dir\file.jpg.encrypt
C:\Dir2
D:\Dir3\Dir4\Dir5\file.jpg.encrypt


==============
4. Adding keys
==============

4.1 Add keys
============
The decryption key is 32 characters long string. You can add up to 1024 decryption keys to ECh0raix Decoder, but each key has to be on separated line.
If you do not have decryption key for you files, please read section 5 (Recovering decryption key).

4.2 From ransom note
====================
If you have valid RSA private key you can decrypt decryption key from ransom note. For decrypting decrytpion key you need last line from the ransom note or ransom note file itself and valid RSA private key or any file that contains the RSA private key (for exmaple decryptor obtained from attackers). If decrypted key is valid it will be automatically added into pool of laoded keys and can be used for decryption of encrypted files.

4.3 From file
=============
You can use a file as a source of potential decryption key. For example attacker's decrypton tool can be loaded. Each possible key from the file will be used for decryption of selected encrypted files. If the right key is found during decryption, this key will be preferred for next encrypted file.

============================
5. Recovering decryption key
============================
ECh0raix Decoder can recover decryption key for your encrypted files. The decryption key can be reconstructed from encrypted files with well known header or from a pair of both encrypted and original file or from a folder with several encrypted files.

5.1 Pair of encrypted and original file
=======================================
If you have a pair of encrypted and unencrypted version of the same file please choose 1st option and select the pair of files. Original file name is extracted from the file name of encrypted files to prevent choosing different file.

5.2 Two encrypted files
=======================
In case you do not have original and encrypted version of the same file, you can select two encrypted files from different groups of known formats.

Supported groups of known formats:
- Old office documents (doc, xls, ppt, dot, xla, wiz) {recommended to use it as 1st selected file}
- New office documents (docx, xlxs, pptx) + zip archive (zip)
- Rar archive (rar)
- 7z archive (7z)
- PDF file (pdf)
- RTF document (rtf)
- PNG file (png)
- JPG (jpg) {if possible avoid using this format as 1st file}

If the 1st file is selected from group Old office documents (for example .doc extension) it is not possible to select another file from this group as 2nd file.

5.3 Exhaustive search
=====================
It will try to bruteforce the whole keyspace, ie 6.277E57 possible combinations.
If you feel lucky tou can try random search, there is statistically higher chance to find the key, but it is still very slim.


5.4 Number of threads
=====================
Searching for the key runs in parallel, so this process can be split to "n" threads. It is recommended to select no more than max number of threads - 1 (this value is preddefined). Choosing more threads can halt the processor, make computer to not be able to respond or damage the processor in case your cooling is not good enough.

