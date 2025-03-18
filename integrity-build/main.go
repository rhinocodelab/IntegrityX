package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type FileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

func remountSDA1RW() error {
	cmd := exec.Command("mount", "-o", "remount,rw", "/sda1")
	return cmd.Run()
}

func remountSDA1RO() {
	cmd := exec.Command("mount", "-o", "remount,ro", "/sda1")
	cmd.Run()
}

func generateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func hideKeyInImage(key []byte, imagePath string) error {
	tempKeyFile := "tempkey.txt"
	if err := os.WriteFile(tempKeyFile, key, 0600); err != nil {
		return err
	}
	defer os.Remove(tempKeyFile)

	cmd := exec.Command("steghide", "embed", "-ef", tempKeyFile, "-cf", imagePath, "-p", "")
	return cmd.Run()
}

func extractKeyFromImage(imagePath string) ([]byte, error) {
	tempKeyFile := "extracted_key.txt"
	cmd := exec.Command("steghide", "extract", "-sf", imagePath, "-xf", tempKeyFile, "-p", "")
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	defer os.Remove(tempKeyFile)

	return os.ReadFile(tempKeyFile)
}

func encryptFile(key []byte, filePath string) error {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(filePath, ciphertext, 0644)
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func scanAndSaveHashes(rootPath string) error {
	var fileHashes []FileHash

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != rootPath {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			hash, err := calculateFileHash(path)
			if err != nil {
				return err
			}
			fileHashes = append(fileHashes, FileHash{Path: path, Hash: hash})
		}
		return nil
	})
	if err != nil {
		return err
	}

	dbPath := filepath.Join(rootPath, ".db.json")
	_ = os.Remove(dbPath)

	jsonData, err := json.MarshalIndent(fileHashes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dbPath, jsonData, 0644)
}

func createFlagFile() error {
	flagFilePath := "/data/.flag"
	flagContent := fmt.Sprintf("Timestamp: %s\nSystem Info: %s\n", time.Now().Format(time.RFC3339), os.Getenv("HOSTNAME"))
	return os.WriteFile(flagFilePath, []byte(flagContent), 0644)
}

func flagExists() bool {
	_, err := os.Stat("/data/.flag")
	return err == nil
}

func main() {
	if flagExists() {
		fmt.Println("Flag file detected. Integrity check already completed. Exiting.")
		return
	}

	if err := remountSDA1RW(); err != nil {
		fmt.Println("Error remounting /sda1:", err)
		remountSDA1RO()
		return
	}

	defer remountSDA1RO()

	if len(os.Args) < 2 {
		fmt.Println("Usage: ./file_integrity <image_path>")
		return
	}
	imagePath := os.Args[1]

	key, err := generateRandomKey()
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	if err := hideKeyInImage(key, imagePath); err != nil {
		fmt.Println("Error hiding key in image:", err)
		return
	}
	directories := []string{
		"/sda1/data/apps/",
		"/sda1/data/basic/",
		"/sda1/data/core/",
		"/sda1/boot/",
	}

	for _, dir := range directories {
		if err := scanAndSaveHashes(dir); err != nil {
			fmt.Printf("Error processing %s: %v\n", dir, err)
		}
	}

	keyFromImage, err := extractKeyFromImage(imagePath)
	if err != nil {
		fmt.Println("Error extracting key from image:", err)
		return
	}

	for _, dir := range directories {
		dbPath := filepath.Join(dir, ".db.json")
		if err := encryptFile(keyFromImage, dbPath); err != nil {
			fmt.Printf("Error encrypting %s: %v\n", dbPath, err)
		}
	}

	createFlagFile()
}
