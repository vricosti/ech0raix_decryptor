package main

import (
	"fmt"
	"os"
)

func main() {

	//os* os_Stat(const void* path, int path_len)
	// arg0: rax
	//.text:000000000048A058 lea     rax, "/home/vince"
	//.text:000000000048A05F mov     ebx, 0Bh
	//.text:000000000048A064 call    os_Stat 			-- os* pFileInfo = os_Stat(rax, ebx)

	path := "/home/vince"
	fileInfo, _ := os.Stat(path)

	//.text:000000000048A069 mov     rcx, [rax+18h]		-- rcx = &pFileInfo.IsDir
	//.text:000000000048A06D mov     rax, rbx			-- rax = ???
	//.text:000000000048A070 call    rcx				-- rax = *pFileInfo.IsDir()
	isdir := fileInfo.IsDir()

	//.text:000000000048A072 test    al, al				-- if rax == 0 goto NOT_A_DIR
	if isdir {
		fmt.Println("path is a dir")
	} else {
	NOT_A_DIR:
		fmt.Println("path is not a dir")
	}

	fmt.Println("exiting")
}
