;4STDs9cmUlkiujXuLkdTouoqOIfER4TE
;D:\Dev\RansomWare\Test
; They had a problem in their decryptor (maybe they still have) what corrupted files bigger than 10MB.
; This ransomware has plenty of issues and one of them is how they handle file encryption. 
; The first odd thing is that they write encrypted bytes 2 times, so encrypted file is 2 times bigger + IV for each block + "ech0raix" marker of course. 
; Another odd thing is that during encryption they reset IV.
; So first what you have to check is if at offset 10*1024*1024 + 16 is the same IV as at the start of the encrypted file. 
; If yes, then you have to reset IV each 10 MB period. If the period is not there, than it is older version and period is 100MB instead of 10MB. 
; Maybe they changed it or fixed their decryptor, but as I said I did not recheck their ransomware nor decryptor for long time. 
; After you handle the period corrently you just have to check if there is "ech0raix" marker in decrypted buffer. 
; You can calculate the original filesize of course, but it is more bullet proof to just check it - more resistent for future changes. 
; That is the reason why I am doing it like that.
;------------------------------------------------------------------------------------------------------------------------------------------------
; FILEBUFFERSIZE equ 10485760
;------------------------------------------------------------------------------------------------------------------------------------------------
align 16
_DecryptFile proc uses esi edi ebx ecx edx lpFilename:DWORD, lpFindData:DWORD, deleteorig:DWORD, version:DWORD

        local hfile_in:DWORD
        local hfile_out:DWORD
        local _exitvalue:DWORD
        local bytesread:DWORD
        local size_low:DWORD
        local size_high:DWORD
        local warning_level:DWORD
        local _nKey:DWORD
        local lpkey:DWORD
        local filecreated:DWORD
        local lpAES:AES
        local _IV[16]:BYTE
        local marker:DWORD
        local echoraixpos:DWORD
        local block_100:DWORD
        local keyfiletested:DWORD
        local period:DWORD

        xor eax,eax
        mov hfile_in,eax
        mov hfile_out,eax
        mov _exitvalue,eax
        mov bytesread,eax
        mov warning_level,eax
        mov _nKey,-1
        mov lpkey,eax
        mov filecreated,eax
        mov marker,eax
        mov block_100,eax
        mov keyfiletested,eax
        mov period,100*1024*1024
        
       ;check version
        mov eax,version
        test eax,eax
        jz _Decrypt_invalidversion
        cmp eax,VERSIONS
        ja _Decrypt_invalidversion
        
       ;open encrypted file
        invoke CreateFile,lpFilename,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0
        cmp eax,-1
        jz _Decrypt_open_err
        mov hfile_in,eax
        
        invoke strlength,lpFilename
        sub eax,8
        push eax
        push lpFilename
        invoke Pis,heap_cesta2,lpstr("$u")

        mov esi,file_mem_in
        mov edi,file_mem_out
        
       ;copy size
        mov edx,lpFindData
        mov eax,(WIN32_FIND_DATAW ptr [edx]).nFileSizeLow
        mov ecx,(WIN32_FIND_DATAW ptr [edx]).nFileSizeHigh
        and eax,not(15)
        mov size_low,eax
        mov size_high,ecx
        
       ;create new file
        invoke CreateFile,heap_cesta2,GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,0,CREATE_ALWAYS,0,0
        cmp eax,-1
        jz _Decrypt_open2_err
        mov hfile_out,eax
        
       ;Get period
        ;Read first 16 bytes
        invoke ReadFile,hfile_in,addr _IV,16,addr bytesread,0
        cmp bytesread,16
        jnz _Decrypt_read_err

        mov bytesread,0
        invoke SetLastError,NO_ERROR
        invoke SetFilePointer,hfile_in,10*1024*1024+16,addr bytesread,FILE_BEGIN
        invoke GetLastError
        test eax,eax
        jnz _Decrypt_gotperiod
        
        invoke ReadFile,hfile_in,esi,16,addr bytesread,0
        cmp bytesread,16
        jnz _Decrypt_gotperiod
        
        invoke datacmp,esi,addr _IV,16
        test eax,eax
        jz _Decrypt_gotperiod
        mov period,10*1024*1024

_Decrypt_gotperiod:
;;DEBUG
__DEBUG lpstr("File: $s, period: $d"),lpFilename,period
;;/DEBUG   

        mov bytesread,0
        invoke SetFilePointer,hfile_in,0,addr bytesread,FILE_BEGIN
        cmp keyfile_mem,0
        jnz _Decrypt_morekeys
        
_Decrypt_findkey:
      ;find correct key from loaded keys
        mov ebx,heap_keys
;        invoke DataCpyN,addr _IV,addr (KEY ptr [ebx]).IV,16
        invoke AES_SetEncryptKey,ebx,addr lpAES
      
        cmp nKeys,1
        jz _Decrypt_readIV

_Decrypt_morekeys:
      ;read marker data
        push ebx
        mov ebx,lpFindData
        mov ecx,period
        mov eax,(WIN32_FIND_DATAW ptr [ebx]).nFileSizeLow
        mov edx,(WIN32_FIND_DATAW ptr [ebx]).nFileSizeHigh
        lea ecx,[ecx*2+32]
        div ecx
        mov ecx,edx
        shr ecx,1
        mov eax,(WIN32_FIND_DATAW ptr [ebx]).nFileSizeLow
        mov edx,(WIN32_FIND_DATAW ptr [ebx]).nFileSizeHigh
        sub eax,ecx
        sbb edx,0
        sub eax,31
        sbb edx,0
        mov ecx,eax
        and ecx,not(15)
        and eax,15
        mov echoraixpos,eax
        mov bytesread,edx
        pop ebx
        invoke SetFilePointer,hfile_in,ecx,addr bytesread,FILE_BEGIN
        
        invoke ReadFile,hfile_in,esi,48,addr bytesread,0
        cmp bytesread,48
        jnz _Decrypt_read_err
        xor ecx,ecx
        mov bytesread,ecx
        invoke SetFilePointer,hfile_in,ecx,addr bytesread,FILE_BEGIN
        
        cmp keyfiletested,0
        jnz _Decrypt_check_setkeys
        
        mov ecx,keyfile_size
        test ecx,ecx
        jz _Decrypt_check_setkeys
        
       ;check keyfile
        mov ebx,keyfile_mem
        mov eax,keyfile_key
        mov edx,echoraixpos
        add edx,edi
        test eax,eax
        jz _Decrypt_test_keyfile_loop
        
       ;test last key from keyfile first
        mov ebx,eax
        invoke AES_SetEncryptKey,ebx,addr lpAES
        invoke AES_CFB_Decrypt,addr [esi+16],edi,32,esi,addr lpAES
        invoke datacmp,edx,offset echoraix_marker,15  
        test eax,eax
        jnz _Decrypt_keyfile_match
        mov ebx,keyfile_mem
        
align 16
_Decrypt_test_keyfile_loop:
        invoke AES_SetEncryptKey,ebx,addr lpAES
        invoke AES_CFB_Decrypt,addr [esi+16],edi,32,esi,addr lpAES
        
        invoke datacmp,edx,offset echoraix_marker,15  
        test eax,eax
        jnz _Decrypt_keyfile_match
        
        inc ebx
        dec ecx
        cmp ecx,32
        jae _Decrypt_test_keyfile_loop
        
       ;if key is not found and there is more keys, test them or load first key from file and go to decrypt
        mov keyfiletested,1
        cmp nKeys,0
        jnz _Decrypt_check_setkeys
        invoke AES_SetEncryptKey,keyfile_mem,addr lpAES
        jmp _Decrypt_readIV
_Decrypt_keyfile_match:
        mov keyfile_key,ebx
      ;/find correct key from loaded file
        jmp _Decrypt_readIV
        
        
       ;check set keys 
align 16
_Decrypt_check_setkeys:
        mov ecx,nKeys
        mov eax,nKey
        mov edx,echoraixpos
        mov _nKey,eax
        add edx,edi
        test eax,eax
        jz _Decrypt_test_key_loop
        
       ;test last key first
        shl eax,5
        lea ecx,[eax+ebx]
        invoke AES_SetEncryptKey,ecx,addr lpAES
        invoke AES_CFB_Decrypt,addr [esi+16],edi,32,esi,addr lpAES
        mov ecx,nKey
        invoke datacmp,edx,offset echoraix_marker,15  
        inc ecx
        test eax,eax
        jnz _Decrypt_key_match
        mov ecx,nKeys
        
       ;test all keys
align 16
_Decrypt_test_key_loop:
        invoke AES_SetEncryptKey,ebx,addr lpAES
        invoke AES_CFB_Decrypt,addr [esi+16],edi,32,esi,addr lpAES
        
        invoke datacmp,edx,offset echoraix_marker,15  
        test eax,eax
        jnz _Decrypt_key_match
        
        add ebx,sizeof(KEY)
        dec ecx
        jnz _Decrypt_test_key_loop
        
       ;if key is not found just load the first key and do not change number of last used key
        invoke AES_SetEncryptKey,heap_keys,addr lpAES
        jmp _Decrypt_readIV
_Decrypt_key_match:
        dec ecx
        mov nKey,ecx
      ;/find correct key from loaded keys

align 16
_Decrypt_readIV:
        invoke ReadFile,hfile_in,addr _IV,16,addr bytesread,0
        cmp bytesread,16
        jnz _Decrypt_read_err
        
        sub size_low,16
        sbb size_high,0
        mov block_100,16
        
align 16        
_Decrypt_loop:
;;DEBUG
__DEBUG lpstr("FileSizeLow: $d, FileSizeHigh: $d"),size_high,size_low
;;/DEBUG  
        xor eax,eax
        mov ebx,FILEBUFFERSIZE
        cmp size_high,eax
        ja @F
        mov eax,size_low
        test eax,eax
        jbe _Decrypt_loop_end
        cmp ebx,eax
        cmova ebx,eax
@@:    
       ;align read buffer if needed
        mov eax,block_100
        add eax,ebx
        cmp eax,period
        jbe _Decrypt_read
       
       ;how many bytes can we read?
        sub eax,period
        sub eax,16
        sub ebx,eax                 ;nbytes to period
        
_Decrypt_read:    
       ;read data from input file
        invoke ReadFile,hfile_in,esi,ebx,addr bytesread,0
;;DEBUG
__DEBUG lpstr("Going to read: $d, Read: $d"),ebx,bytesread
;;/DEBUG

        cmp bytesread,ebx
        jz @F
        invoke GetLastError
        test eax,eax
        jnz _Decrypt_read_err     
@@:
             
       ;decrypt
        invoke AES_CFB_Decrypt,esi,edi,ebx,addr _IV,addr lpAES
        test eax,eax
        jz _Decrypt_aes_err

       ;search for ECh0raix marker
        invoke datafind,edi,ebx,lpastr("eCh0raix"),8
        test eax,eax
        jz @F
       ;correction of original filesize
        sub eax,edi
        lea ebx,[eax-7]
        mov marker,1
@@:        
       ;write decrypted data 
        invoke WriteFile,hfile_out,edi,ebx,addr bytesread,0
        test eax,eax
        jz _Decrypt_write_err
        cmp bytesread,ebx
        jnz _Decrypt_write_err
        
       ;prepare IV
        invoke DataCpyN,addr _IV,addr [esi+ebx-16],16

        cmp marker,1
        jz _Decrypt_finish
        mov ecx,period
        add block_100,ebx
        add ecx,16
        cmp block_100,ecx
        jnz @F
        mov bytesread,0
        invoke SetFilePointer,hfile_in,ecx,addr bytesread,FILE_CURRENT
        invoke ReadFile,hfile_in,addr _IV,16,addr bytesread,0
        cmp bytesread,16
        jnz _Decrypt_read_err
        mov eax,period
        add eax,16
        sub size_low,eax
        sbb size_high,0
        mov block_100,16
@@:     
        sub size_low,ebx
        ja _Decrypt_loop
        sbb size_high,0
        jmp _Decrypt_loop
        
align 16
_Decrypt_loop_end:
       ;marker was not found during decryption
        inc warning_level
        push heap_cesta2
        invoke Pis,file_mem_out,lpstr("WARNING - Marker not found. Keeping original file. Decrypted file is probably corrupted: $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_finish

_Decrypt_finish:
        mov edx,lpFindData
        invoke SetFileTime,hfile_out,addr (WIN32_FIND_DATAW ptr [edx]).ftCreationTime,addr (WIN32_FIND_DATAW ptr [edx]).ftLastAccessTime,addr (WIN32_FIND_DATAW ptr [edx]).ftLastWriteTime

        invoke GetFileAttributes,lpFilename
        cmp eax,-1
        jz @F
        invoke SetFileAttributes,heap_cesta2,eax
@@:
        mov _exitvalue,1
        cmp deleteorig,1
        jnz @F
        cmp warning_level,0
        jnz @F
        invoke CloseHandle,hfile_in
        invoke CloseHandle,hfile_out
        mov hfile_in,0
        mov hfile_out,0
        invoke DeleteFile,lpFilename
@@:        
        cmp warning_level,0
        jnz @F
        push heap_cesta2
        invoke Pis,file_mem_out,lpstr("DECRYPTED: $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        inc files_decrypted
@@:
        cmp warning_level,0
        jz @F
        inc files_warning
@@:

_Decrypt_end:
        cmp hfile_in,0
        jz @F
        invoke CloseHandle,hfile_in     
@@:     cmp hfile_out,0
        jz @F
        invoke CloseHandle,hfile_out     
@@:     
       ;remove created file if skipped
        cmp filecreated,1
        jnz @F
        cmp _exitvalue,0
        jnz @F
        invoke DeleteFile,heap_cesta2     
@@:
        mov eax,_exitvalue
        ret


_Decrypt_invalidversion:
        inc files_skipped
        push lpFilename
        invoke Pis,file_mem_out,lpstr("ERROR - Unable to determine version of input file: $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end

_Decrypt_open_err:
        inc files_skipped
        push lpFilename
        invoke GetLastError
        push eax
        invoke Pis,file_mem_out,lpstr("ERROR - Unable to open input file (Error: $h): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end

_Decrypt_open2_err:
        inc files_skipped
        push heap_cesta2
        invoke GetLastError
        push eax
        invoke Pis,file_mem_out,lpstr("ERROR - Unable to create output file (Error: $h): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out               
        jmp _Decrypt_end  

_Decrypt_read_err:
        inc files_skipped
        push lpFilename
        invoke GetLastError
        push eax
        invoke Pis,file_mem_out,lpstr("ERROR - Unable to read input file (Error: $h): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end

_Decrypt_write_err:
        inc files_skipped
        push heap_cesta2
        invoke GetLastError
        push eax
        invoke Pis,file_mem_out,lpstr("SKIPPED - Unable to write to file (Error: $h): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end

_Decrypt_wrong_key:
        inc files_skipped
        push lpFilename
        invoke Pis,file_mem_out,lpstr("SKIPPED - Header doesn't match with loaded keys. (Encrypted with different key): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end

_Decrypt_aes_err:
        inc files_skipped
        push lpFilename
        invoke Pis,file_mem_out,lpstr("SKIPPED - Unable to decrypt file (AES internal error): $s",NEWLINE)
        invoke AddToLogFile,file_mem_out
        jmp _Decrypt_end


_DecryptFile endp