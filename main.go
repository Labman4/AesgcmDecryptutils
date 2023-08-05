package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"os"
	"flag"
	"strconv"
	"strings"
	"fmt"
)

type Config struct {
	filePath string
	exportPath string
	secret string
	chunkSize string
	
}

func main() {
	config := readConfigFromCommandLine()
	bytes, err := os.ReadFile(config.filePath)
	if err != nil {
		panic(err)
	}
	chunkSize, err := parseSize(config.chunkSize)
	if err != nil {
		panic(err)
	}
	sha256Hash := sha256ByteArray(config.secret)
	decrypt := decryptChunk(bytes, sha256Hash, chunkSize + 28)
	err = os.WriteFile(config.exportPath, decrypt, 0644)
	if err != nil {
		panic(err)
	}
}

func readConfigFromCommandLine() Config {
	var filePath string
	var exportPath string
	var secret string
	var chunkSize string
	flag.StringVar(&filePath, "filePath", "", "filePath")
	flag.StringVar(&exportPath, "exportPath", "", "exportPath");
	flag.StringVar(&secret, "secret", "", "secret")
	flag.StringVar(&chunkSize, "chunkSize", "5mb", "chunkSize")
	flag.Parse()
	config := Config{
		filePath: filePath,
		exportPath: exportPath,
		secret: secret,
		chunkSize: chunkSize,
	}
	return config
}

func sha256ByteArray(input string) []byte {
	hash := sha256.New()
	hash.Write([]byte(input))
	return hash.Sum(nil)
}

func decryptChunk(ciphertext []byte, key []byte, chunkSize int) []byte {
	numOfChunks := (len(ciphertext) + chunkSize - 1) / chunkSize
	originLength := len(ciphertext) - (numOfChunks * 28)
	decrypt := make([]byte, originLength)
	decryptoffset := 0;
	for i := 0; i < numOfChunks; i++ {
		start := i * chunkSize
		length := chunkSize
		if start+length > len(ciphertext) {
			length = len(ciphertext) - start
		}
		chunk := make([]byte, length)
		copy(chunk, ciphertext[start:start+length])
		decrypted := decryptBytes(chunk, key)
		copy(decrypt[start:decryptoffset+len(decrypted)], decrypted)
		decryptoffset += len(decrypted)
	}
	return decrypt
}

func decryptBytes(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	decrypted, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return decrypted
}

func parseSize(sizeStr string) (int, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	unit := sizeStr[len(sizeStr)-2:]
	valueStr := sizeStr[:len(sizeStr)-2]
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, err
	}
	switch unit {
	case "kb":
		return value * 1024, nil
	case "mb":
		return value * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid size unit, use kb or mb")
	}
}