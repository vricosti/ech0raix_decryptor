package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//const key = "4STDs9cmUlkiujXuLkdTouoqOIfER4TE"

func decryptFile(key string, srcpath string) {
	fmt.Printf("UnLock: %s\n", srcpath)

	ext := filepath.Ext(srcpath)
	if ext != ".encrypt" {
		log.Fatal("not a ech0raix encrypted file - must end with .encrypt")
	}

	dstpath := strings.TrimSuffix(srcpath, ext)
	content, err := ioutil.ReadFile(srcpath)
	if err != nil {
		panic(err.Error())
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}

	iv := content[:aes.BlockSize]
	cyphertext := content[aes.BlockSize:]
	plaintext := make([]byte, len(content)-aes.BlockSize)

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, cyphertext)

	f, err := os.Create(dstpath)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(plaintext))
	if err != nil {
		panic(err.Error())
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
				if file_len > 16 {
					decryptFile(key, path)
				}
			}
		}
		return nil
	})

	//return

	// //https://levelup.gitconnected.com/a-short-guide-to-encryption-using-go-da97c928259f
	// infile, err := os.Open("/home/vince/Dev/ech0raix/Free.jpg.encrypt")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer infile.Close()

	// // The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// // 32 bytes (AES-256)
	// block, err := aes.NewCipher([]byte(key))
	// if err != nil {
	// 	log.Panic(err)
	// }

	// // Never use more than 2^32 random nonces with a given key
	// // because of the risk of repeat.
	// fi, err := infile.Stat()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// //43 5a
	// iv := make([]byte, aes.BlockSize)
	// infile.Read(iv)
	// infile.Seek(0, 0)
	// msgLen := fi.Size() - int64(len(iv))
	// log.Printf("Input file is %d bytes", msgLen)
	// // _, err = infile.ReadAt(iv, msgLen)
	// // if err != nil {
	// // 	log.Fatal(err)
	// // }

	// outfile, err := os.OpenFile("/home/vince/Dev/ech0raix/Free.jpg", os.O_RDWR|os.O_CREATE, 0777)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer outfile.Close()

	// // The buffer size must be multiple of 16 bytes
	// buf := make([]byte, 16)
	// stream := cipher.NewCFBDecrypter(block, iv)
	// for {
	// 	n, err := infile.Read(buf)
	// 	if n > 0 {
	// 		// // The last bytes are the IV, don't belong the original message
	// 		// if n > int(msgLen) {
	// 		// 	n = int(msgLen)
	// 		// }
	// 		// msgLen -= int64(n)

	// 		stream.XORKeyStream(buf, buf[:n])
	// 		// Write into file
	// 		outfile.Write(buf[:n])
	// 	}

	// 	if err == io.EOF {
	// 		break
	// 	}

	// 	if err != nil {
	// 		log.Printf("Read %d bytes: %v", n, err)
	// 		break
	// 	}
	// }
}

// func main() {
// 	//decryptFile("/home/vince/Dev/ech0raix/Free.jpg.encrypt")

// 	infile, err := os.Open("/home/vince/Dev/ech0raix/Free.jpg.encrypt")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer infile.Close()

// 	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
// 	// 32 bytes (AES-256)
// 	key := "4STDs9cmUlkiujXuLkdTouoqOIfER4TE"
// 	block, err := aes.NewCipher([]byte(key))
// 	if err != nil {
// 		log.Panic(err)
// 	}

// 	// Never use more than 2^32 random nonces with a given key
// 	// because of the risk of repeat.
// 	fi, err := infile.Stat()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	iv := make([]byte, block.BlockSize())
// 	msgLen := fi.Size() - int64(len(iv))
// 	_, err = infile.ReadAt(iv, msgLen)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	outfile, err := os.OpenFile("/home/vince/Dev/ech0raix/Free.jpg", os.O_RDWR|os.O_CREATE, 0777)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer outfile.Close()

// 	// The buffer size must be multiple of 16 bytes
// 	buf := make([]byte, 1024)
// 	stream := cipher.NewCFBDecrypter(block, iv)
// 	for {
// 		n, err := infile.Read(buf)
// 		if n > 0 {
// 			// The last bytes are the IV, don't belong the original message
// 			if n > int(msgLen) {
// 				n = int(msgLen)
// 			}
// 			msgLen -= int64(n)
// 			stream.XORKeyStream(buf, buf[:n])
// 			// Write into file
// 			outfile.Write(buf[:n])
// 		}

// 		if err == io.EOF {
// 			break
// 		}

// 		if err != nil {
// 			log.Printf("Read %d bytes: %v", n, err)
// 			break
// 		}
// 	}
// }
