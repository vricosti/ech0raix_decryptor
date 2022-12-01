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
	"bytes"
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

const _10MB_ = (10 * 1024 * 1024)   //10485760
const _100MB_ = (100 * 1024 * 1024) //104857600

const FILEBUFFERSIZE = _10MB_

var period = -1

func UNUSED(x ...interface{}) {}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func trimFileExtension(fileName string) (filename string, ext string) {
	ext = filepath.Ext(fileName)
	return strings.TrimSuffix(fileName, ext), ext
}

func findSubBufferPos(bigbuf []byte, buf []byte) int64 {
	for i := 0; i <= len(bigbuf)-len(buf); i++ {
		suba := bigbuf[i : i+len(buf)]
		if bytes.Equal(suba, buf) {
			return int64(i)
		}
	}
	return -1
}

func seekRead(inFile *os.File, offset int64, buf []byte) (n int, err error) {
	n = 0
	_, err = inFile.Seek(offset, 0)
	if err == nil {
		n, err = io.ReadFull(inFile, buf)
	}
	return n, err
}

func seekReadCmp(inFile *os.File, offset int64, refBuf []byte) (found bool, err error) {
	buf := make([]byte, len(refBuf))
	bytesread, _ := seekRead(inFile, offset, buf)
	if bytesread == len(refBuf) && bytes.Equal(buf, refBuf) {
		found = true
	}
	return found, err
}

func findPeriod(inFile *os.File, filesize int64, iv []byte) int {
	periodFound := int64(0)

	// Check if period is filesize/2-16
	found, _ := seekReadCmp(inFile, filesize/2, iv)
	periodFound = If(found, filesize/2-16, 0)
	if periodFound <= 0 {
		// Check if period is _10MB_
		found, _ := seekReadCmp(inFile, 16+_10MB_, iv)
		periodFound = If(found, int64(_10MB_), 0)
		if periodFound <= 0 {
			// Check if period is _100MB_
			found, _ := seekReadCmp(inFile, 16+_100MB_, iv)
			periodFound = If(found, int64(_100MB_), 0)
		}
	}

	//We could not find a known period so read 200MB max and try to find one
	if periodFound <= 0 && filesize <= 2*_100MB_+16 {
		tmpbuf := make([]byte, 2*_100MB_+16)
		bytesread, _ := seekRead(inFile, 16, tmpbuf)
		if bytesread > 0 {
			periodFound = findSubBufferPos(tmpbuf, iv)
		}
	}

	return int(periodFound)
}

func findEch0raixMarker(buf []byte) (pos int) {
	//00 00 00 00 00 00 00 65 43 68 30 72 61 69 78
	marker := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 'e', 'C', 'h', '0', 'r', 'a', 'i', 'x'}
	return int(findSubBufferPos(buf, marker))
}

func decryptFile(inputName string, outputName string, key []byte, deleteCiphered bool) {

	fi, _ := os.Stat(inputName)
	fmt.Printf("Decrypting: %s (%d)\n", inputName, fi.Size())
	if fi.Size() <= 16 {
		fmt.Printf("File is too small %d => skip\n", fi.Size())
		return
	}
	if _, err := os.Stat(outputName); err == nil {
		if fi_out, _ := os.Stat(outputName); fi_out.Size() > 0 {
			fmt.Println("A filename withtout the .encrypt already exists => skip")
			return
		}
	}

	// Open the input and output files
	inFile, err := os.OpenFile(inputName, os.O_RDONLY, 0)
	check(err)
	defer func(inFile *os.File) { _ = inFile.Close() }(inFile)
	outFile, err := os.OpenFile(outputName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	check(err)
	defer func(outFile *os.File) { _ = outFile.Close() }(outFile)

	// read first 16 bytes that normally corresponds to iv
	iv := make([]byte, 16)
	_, err = io.ReadFull(inFile, iv[:])
	check(err)

	// find period
	period = findPeriod(inFile, fi.Size(), iv)
	if period < 0 {
		fmt.Printf("Cannot find period of this file => skip\n")
		outFile.Close()
		os.Remove(outputName)
		return
	}

	//bitwiseNotMinus15 := int64(math.MaxInt64 - 15)
	//periodAligned := (period & bitwiseNotMinus15) + 16
	//fmt.Printf("period (16 bytes aligned): %d (original period %d)\n", periodAligned, period)

	// Go back to begin of file
	_, err = inFile.Seek(0, 0)
	check(err)

	// Create the cipher object and decrypt the data
	block, err := aes.NewCipher([]byte(key))
	check(err)

	var stream cipher.Stream = nil
	input_buffer := make([]byte, period)
	decrypted_bytes := make([]byte, period)
	read_len, total_len := 0, int64(0)
	new_period := true
	for ok := true; ok; ok = (read_len > 0) {
		if new_period {
			new_period = false
			read_len, err = io.ReadFull(inFile, iv[:])
			if read_len > 0 && err == nil {
				stream = cipher.NewCFBDecrypter(block, iv)
				total_len += int64(read_len)
			} else {
				fmt.Printf("Could not read iv buffer\n")
			}
		}

		read_len, err = inFile.Read(input_buffer)
		if read_len > 0 && err == nil {
			stream.XORKeyStream(decrypted_bytes, input_buffer)
			markerPos := findEch0raixMarker(decrypted_bytes)
			// ech0raix marker was not found => keep on decrypting
			if markerPos == -1 {
				total_len += int64(read_len)
				_, err = outFile.Write(decrypted_bytes)
				if err == nil {
					total_len, err = inFile.Seek(int64(16+period), 1)
					if err == nil {
						new_period = true
					}
				}
			} else {
				// We have found the ech0raix marker
				total_len += int64(markerPos + 1)
				_, err = outFile.Write(decrypted_bytes[0:markerPos])
				if err == nil {
					inFile.Close()
					outFile.Close()
					fmt.Printf("File was successflully decrypted (period = %d)\n", period)
					if deleteCiphered {
						err = os.Remove(inputName)
						fmt.Printf("Encrypted file removal: %s\n", If(err == nil, "OK", "KO"))
					}
					break
				}
			}
		} else {
			fmt.Printf("Could not read file\n")
		}
	}
}

// WORK IN PROGRESS
func walk_bottom_up(root_dir string) {
	file, err := os.Open(root_dir)
	if err != nil {
		log.Fatalf("failed opening directory: %s", err)
	}
	defer file.Close()

	list, _ := file.Readdirnames(0) // 0 to read all files and folders
	for _, name := range list {
		fmt.Println(name)
	}
}

func main() {

	var key string
	var delete_ciphered_files bool
	var start_dir string

	flag.StringVar(&key, "k", "YOUR_32_BYTES_KEY", "your key")
	flag.BoolVar(&delete_ciphered_files, "d", false, "delete ciphered files")
	flag.StringVar(&start_dir, "s", ".", "directory from where we start to decrypt files")

	flag.Parse()

	if flag.NFlag() < 2 {
		fmt.Println("Usage: ech0raix_decryptor -k YOUR_KEY [-c] -s rootdir")
		fmt.Println("   Example: ech0raix_decryptor -k 4STDs9cmUlkiujXuLkdTouoqOIfER4TE -s .")
		fmt.Println("   Example: ech0raix_decryptor -k 4STDs9cmUlkiujXuLkdTouoqOIfER4TE -s /share/data")
		fmt.Println("   Example: ech0raix_decryptor -d -k 4STDs9cmUlkiujXuLkdTouoqOIfER4TE -s /share/data")
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

	walk_bottom_up(start_dir)

	filepath.Walk(start_dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
		}
		fmt.Printf("Current path: %s\n", path)

		if !info.IsDir() {

			_, filename := filepath.Split(path)
			file_ext := strings.ToLower(filepath.Ext(filename))
			readme_file := strings.ToLower("README_FOR_DECRYPT.txt")
			if strings.HasPrefix(strings.ToLower(filename), readme_file) {
				fmt.Printf("Removing %s\n", path)
				os.Remove(path)
			} else if file_ext == ".encrypt" {
				dstpath := strings.TrimSuffix(path, file_ext)
				decryptFile(path, dstpath, []byte(key), delete_ciphered_files)
			}
		}
		return nil
	})
}
