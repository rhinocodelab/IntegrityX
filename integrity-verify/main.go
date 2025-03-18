package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

func extractKeyFromImage(imagePath string) ([]byte, error) {
	tempKeyFile := "extracted_key.txt"
	cmd := exec.Command("steghide", "extract", "-sf", imagePath, "-xf", tempKeyFile, "-p", "")
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	defer os.Remove(tempKeyFile)

	return os.ReadFile(tempKeyFile)
}

func decryptFile(key []byte, filePath string) ([]byte, error) {
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
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

func verifyDirectory(key []byte, dirPath string) (bool, error) {
	dbPath := filepath.Join(dirPath, ".db.json")

	// Decrypt the hash database
	decryptedData, err := decryptFile(key, dbPath)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt .db.json: %v", err)
	}

	// Parse the stored hashes
	var storedHashes []FileHash
	if err := json.Unmarshal(decryptedData, &storedHashes); err != nil {
		return false, fmt.Errorf("failed to parse .db.json: %v", err)
	}

	// Create a map of stored paths for quick lookup
	storedPaths := make(map[string]bool)
	for _, h := range storedHashes {
		storedPaths[h.Path] = true
	}

	// Verify existing files
	allMatch := true
	for _, storedHash := range storedHashes {
		currentHash, err := calculateFileHash(storedHash.Path)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("File missing: %s\n", storedHash.Path)
				allMatch = false
				continue
			}
			return false, fmt.Errorf("failed to calculate hash for %s: %v", storedHash.Path, err)
		}

		if currentHash != storedHash.Hash {
			fmt.Printf("Hash mismatch for %s\n", storedHash.Path)
			fmt.Printf("Stored: %s\nCurrent: %s\n", storedHash.Hash, currentHash)
			allMatch = false
		}
	}

	// Check for new files (informational only)
	newFilesFound := false
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dirPath {
			return filepath.SkipDir
		}
		if !info.IsDir() && path != dbPath {
			if !storedPaths[path] {
				fmt.Printf("New file added: %s\n", path)
				newFilesFound = true
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("failed to scan directory: %v", err)
	}

	if newFilesFound {
		fmt.Println("Note: New files detected, but this does not affect the integrity check of original files.")
	}

	return allMatch, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./file_verifier <image_path>")
		return
	}
	imagePath := os.Args[1]

	// Extract encryption key from image
	key, err := extractKeyFromImage(imagePath)
	if err != nil {
		fmt.Println("Error extracting key from image:", err)
		return
	}

	if err := remountSDA1RW(); err != nil {
		fmt.Println("Error remounting /sda1:", err)
		remountSDA1RO()
		return
	}
	defer remountSDA1RO()

	directories := []string{
		"/sda1/data/apps/",
		"/sda1/data/basic/",
		"/sda1/data/core/",
		"/sda1/boot/",
	}

	allValid := true
	for _, dir := range directories {
		fmt.Printf("\nVerifying directory: %s\n", dir)
		valid, err := verifyDirectory(key, dir)
		if err != nil {
			fmt.Printf("Error verifying %s: %v\n", dir, err)
			allValid = false
			continue
		}
		if valid {
			fmt.Printf("All original files in %s verified successfully\n", dir)
		} else {
			fmt.Printf("Integrity check failed for original files in %s\n", dir)
			allValid = false
		}
	}

	if allValid {
		fmt.Println("\nAll directories' original files verified successfully")
	} else {
		fmt.Println("\nVerification failed for one or more directories' original files")
	}
}
