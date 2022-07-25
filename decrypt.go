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
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//const key = "4STDs9cmUlkiujXuLkdTouoqOIfER4TE"
const default_buffer_size = 65536

func UNUSED(x ...interface{}) {}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func decryptFile(inputName string, outputName string, key []byte) {
	fmt.Printf("Decrypting: %s\n", inputName)

	// Create the cipher object and decrypt the data
	block, err := aes.NewCipher([]byte(key))
	check(err)

	// Open the input and output files
	inFile, err := os.Open(inputName)
	check(err)
	defer func(inFile *os.File) { _ = inFile.Close() }(inFile)
	outFile, err := os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	check(err)
	defer func(outFile *os.File) { _ = outFile.Close() }(outFile)

	// get the size of the ciphered data
	fi, _ := inFile.Stat()
	check(err)
	data_len := int(fi.Size()) - aes.BlockSize
	fmt.Printf("crypted file: %d, datalen = %d (file - 16)", fi.Size(), data_len)

	// read the iv from input file and move the seek pointer just after
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(inFile, iv[:])
	check(err)
	_, _ = inFile.Seek(aes.BlockSize, 0)

	// Set buffer size
	buffer_size := default_buffer_size

	// decode ciphered data
	stream := cipher.NewCFBDecrypter(block, iv)
	input_buffer := make([]byte, buffer_size)
	decrypted_bytes := make([]byte, buffer_size)
	read_len, total_len := 0, 0
	for ok := true; ok; ok = (read_len > 0) {
		read_len, _ = inFile.Read(input_buffer)
		total_len += read_len

		if read_len == buffer_size {
			stream.XORKeyStream(decrypted_bytes, input_buffer)
			_, _ = outFile.Write(decrypted_bytes)
		} else if read_len > 0 {
			stream.XORKeyStream(decrypted_bytes, input_buffer)
			tmp_buffer := decrypted_bytes[0:read_len]
			_, _ = outFile.Write(tmp_buffer)
			//fmt.Println("What should I do ?????")
		}
	}
}

// This method is from https://github.com/Akegarasu/file-encrypter/blob/main/main.go
// But it doesn't work very well either because when I decrypt tests/Windows7_Home.vmx
// I also get the same garbage at then end
// However the code is simpler.
func decryptFile2(inputName string, outputName string, key []byte) {
	var cfb cipher.Stream
	var err error
	iv := make([]byte, aes.BlockSize)
	inFile, err := os.Open(inputName)
	if err != nil {
		log.Fatal("open input file failed")
	}
	defer func(inFile *os.File) { _ = inFile.Close() }(inFile)
	outFile, err := os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Fatal("open output file failed")
	}
	defer func(outFile *os.File) { _ = outFile.Close() }(outFile)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.ReadFull(inFile, iv[:])
	if err != nil {
		log.Fatal(err)
	}
	_, _ = inFile.Seek(aes.BlockSize, 0)
	cfb = cipher.NewCFBDecrypter(block, iv)

	s := cipher.StreamReader{
		S: cfb,
		R: inFile,
	}
	if _, err = io.Copy(outFile, s); err != nil {
		log.Println(err)
	}
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
		fmt.Println("Error: the key should be 32 bytes long")
	}
	if len(start_dir) == 0 {
		fmt.Println("Error: invalid empty path")
	}

	if start_dir[0:1] != "/" {
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
				if file_len > 16 {
					dstpath := strings.TrimSuffix(path, file_ext)
					decryptFile(path, dstpath, []byte(key))
				}
			}
		}
		return nil
	})
}
