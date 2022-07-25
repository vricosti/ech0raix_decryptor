////////////////////////////////////////////////////////////////////////////////
// Copyright 2022 Vince Ricosti
// This code is a free and virus free implementation of the ech0raix decoder
// if you have been infected by ech0raix (aka qnap encrypt) and you have paid
// you should have received a zip file containing some binaries for different
// platforms.
// Personnaly even if I have checked that the binary was virus free I prefer to
// execute a well-known code and I advise you to do the same.
// Personal message to the guy who has encrypted my data:
// Karma will come back very hard on you and I wish you will die from a
// rectum's cancer
////////////////////////////////////////////////////////////////////////////////

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//const key = "4STDs9cmUlkiujXuLkdTouoqOIfER4TE"
const buffer_size = 65536

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func UNUSED(x ...interface{}) {}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func UNUSED(x ...interface{}) {}

func decryptFile(key string, srcpath string) {
	fmt.Printf("UnLock: %s\n", srcpath)

	ext := filepath.Ext(srcpath)
	if ext != ".encrypt" {
		log.Fatal("not a ech0raix encrypted file - must end with .encrypt")
	}
	dstpath := strings.TrimSuffix(srcpath, ext)

	// Create the cipher object and decrypt the data
	block, err := aes.NewCipher([]byte(key))
	check(err)

	// Open the input and output files
	input_file, err := os.Open(srcpath)
	check(err)
	output_file, err := os.Create(dstpath)
	check(err)

	// read the iv from input file
	iv := make([]byte, aes.BlockSize)
	n1, err := input_file.Read(iv)
	UNUSED(n1)
	check(err)

	// read b
	stream := cipher.NewCFBDecrypter(block, iv)
	input_buffer := make([]byte, buffer_size)
	decrypted_bytes := make([]byte, buffer_size)
	buflen := 0
	for ok := true; ok; ok = (buflen > 0) {
		buflen, _ = input_file.Read(input_buffer)
		stream.XORKeyStream(decrypted_bytes, input_buffer)
		_, _ = output_file.Write(decrypted_bytes)
	}
	input_file.Close()
	output_file.Close()
}

func main() {

	var key string
	var keep_ciphered_files bool
	var start_dir string

	flag.StringVar(&key, "k", "YOUR_32_BYTES_KEY", "your key")
	flag.BoolVar(&keep_ciphered_files, "c", false, "keep ciphered files")
	flag.StringVar(&start_dir, "s", ".", "directory from where we start to decrypt files")

	flag.Parse()

	if flag.NFlag() < 2 {
		fmt.Println("Usage: ech0raix_decryptor -k YOUR_KEY [-c] -s rootdir")
		fmt.Println("   Example: ech0raix_decryptor -k 5FRDs9cmUlkiujXuLkdTouoqOIfER3TD -s .")
		fmt.Println("   Example: ech0raix_decryptor -k 5FRDs9cmUlkiujXuLkdTouoqOIfER3TD -s /share/data")
		fmt.Println("   Example: ech0raix_decryptor -c -k 5FRDs9cmUlkiujXuLkdTouoqOIfER3TD -s /share/data")
		os.Exit(1)
	}

	if len(key) != 32 {
		fmt.Println("Error the key should be 32 bytes long")
	}

	if strings.HasPrefix(start_dir, ".") {
		tmp_path, _ := filepath.Abs(start_dir)
		flag.Set("s", tmp_path)
	}

	if stat, err := os.Stat(start_dir); err != nil || !stat.IsDir() {
		fmt.Println("Start directory does not exists")
		os.Exit(1)
	}

	filepath.Walk(start_dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
		}
		if !info.IsDir() {
			file_ext := filepath.Ext(path)
			if file_ext == ".encrypt" {
				file_len := info.Size()
				if file_len > 16 && file_len < 512000000 {
					decryptFile(key, path)
				}
			}
		}
		return nil
	})
}
