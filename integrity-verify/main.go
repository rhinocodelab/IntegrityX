package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jung-kurt/gofpdf"
	"gopkg.in/ini.v1"
)

type DBHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

type FileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

type ReportEntry struct {
	Directory string
	Status    string
	Details   []string
	NewFiles  []string
}

func remountSDA1RW() error {
	fmt.Println("Remounting /sda1 as read-write")
	cmd := exec.Command("mount", "-o", "remount,rw", "/sda1")
	return cmd.Run()
}

func remountSDA1RO() {
	fmt.Println("Remounting /sda1 as read-only")
	cmd := exec.Command("mount", "-o", "remount,ro", "/sda1")
	cmd.Run()
}

func extractKeyFromImage(imagePath string) ([]byte, error) {
	fmt.Printf("Extracting key from image: %s\n", imagePath)
	tempKeyFile := "extracted_key.txt"
	cmd := exec.Command("steghide", "extract", "-sf", imagePath, "-xf", tempKeyFile, "-p", "")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("steghide extraction failed: %v", err)
	}
	defer os.Remove(tempKeyFile)
	key, err := os.ReadFile(tempKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read extracted key: %v", err)
	}
	return key, nil
}

func encryptFile(key, plaintext []byte) ([]byte, error) {
	fmt.Println("Encrypting data")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptFile(key []byte, filePath string) ([]byte, error) {
	fmt.Printf("Decrypting file: %s\n", filePath)
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}
	return plaintext, nil
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

func verifyDirectory(key []byte, dirPath string) (bool, ReportEntry, error) {
	dbPath := filepath.Join(dirPath, ".db.json")
	baseName := filepath.Base(dirPath)
	hashFilePath := filepath.Join(dirPath, fmt.Sprintf(".%s.json", baseName))
	entry := ReportEntry{Directory: dirPath}

	allMatch := true

	// Step 1: Verify the .apps.json file
	if _, err := os.Stat(hashFilePath); err == nil {
		// Decrypt .apps.json
		decryptedHashData, err := decryptFile(key, hashFilePath)
		if err != nil {
			entry.Status = "Error"
			entry.Details = append(entry.Details, fmt.Sprintf("Failed to decrypt %s: %v", hashFilePath, err))
			return false, entry, err
		}

		var dbHash DBHash
		if err := json.Unmarshal(decryptedHashData, &dbHash); err != nil {
			entry.Status = "Error"
			entry.Details = append(entry.Details, fmt.Sprintf("Failed to parse %s: %v", hashFilePath, err))
			return false, entry, err
		}

		// Verify the path matches
		if dbHash.Path != dbPath {
			detail := fmt.Sprintf("Path mismatch in %s\n  Stored: %s\n  Expected: %s", hashFilePath, dbHash.Path, dbPath)
			entry.Details = append(entry.Details, detail)
			fmt.Println(detail)
			allMatch = false
		}

		// Calculate current hash of .db.json and compare
		currentDBHash, err := calculateFileHash(dbPath)
		if err != nil {
			entry.Status = "Error"
			entry.Details = append(entry.Details, fmt.Sprintf("Failed to calculate hash for %s: %v", dbPath, err))
			return false, entry, err
		}

		if currentDBHash != dbHash.Hash {
			detail := fmt.Sprintf("Hash mismatch for %s\n  Stored: %s\n  Current: %s", dbPath, dbHash.Hash, currentDBHash)
			entry.Details = append(entry.Details, detail)
			fmt.Println(detail)
			allMatch = false
		} else {
			fmt.Printf("%s hash verified successfully\n", hashFilePath)
		}
	} else if os.IsNotExist(err) {
		entry.Details = append(entry.Details, fmt.Sprintf("Warning: %s not found - cannot verify .db.json integrity", hashFilePath))
		allMatch = false
	} else {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to check %s existence: %v", hashFilePath, err))
		return false, entry, err
	}

	// Step 2: Verify the .db.json contents (existing code)
	decryptedData, err := decryptFile(key, dbPath)
	if err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to decrypt .db.json: %v", err))
		return false, entry, err
	}

	var storedHashes []FileHash
	if err := json.Unmarshal(decryptedData, &storedHashes); err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to parse .db.json: %v", err))
		return false, entry, err
	}

	storedPaths := make(map[string]string)
	for _, h := range storedHashes {
		storedPaths[h.Path] = h.Hash
	}

	// Check for missing files and hash mismatches
	for path, storedHash := range storedPaths {
		currentHash, err := calculateFileHash(path)
		if err != nil {
			if os.IsNotExist(err) {
				detail := fmt.Sprintf("File missing: %s", path)
				fmt.Println(detail)
				entry.Details = append(entry.Details, detail)
				allMatch = false
				continue
			}
			entry.Status = "Error"
			entry.Details = append(entry.Details, fmt.Sprintf("Failed to calculate hash for %s: %v", path, err))
			return false, entry, err
		}

		if currentHash != storedHash {
			detail := fmt.Sprintf("Hash mismatch for %s\n  Stored: %s\n  Current: %s", path, storedHash, currentHash)
			fmt.Println(detail)
			entry.Details = append(entry.Details, detail)
			allMatch = false
		}
	}

	// Check for unauthorized new files
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dirPath {
			return filepath.SkipDir
		}
		if !info.IsDir() && path != dbPath && path != hashFilePath {
			if _, exists := storedPaths[path]; !exists {
				detail := fmt.Sprintf("Unauthorized new file detected: %s", path)
				fmt.Println(detail)
				entry.Details = append(entry.Details, detail)
				entry.NewFiles = append(entry.NewFiles, path)
				allMatch = false
			}
		}
		return nil
	})
	if err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to scan directory: %v", err))
		return false, entry, err
	}

	if allMatch {
		entry.Status = "Success"
		fmt.Printf("All files in %s verified successfully - no unauthorized changes or additions\n", dirPath)
	} else {
		entry.Status = "Failed"
		fmt.Printf("Integrity check failed for %s\n", dirPath)
	}

	return allMatch, entry, nil
}

func updateDirectory(key []byte, updateFile string) error {
	fmt.Println("Starting directory update process")
	if err := remountSDA1RW(); err != nil {
		return fmt.Errorf("failed to remount /sda1 as read-write: %v", err)
	}
	defer remountSDA1RO()

	fmt.Printf("Loading update file: %s\n", updateFile)
	cfg, err := ini.Load(updateFile)
	if err != nil {
		return fmt.Errorf("failed to read update.ini: %v", err)
	}

	for _, section := range cfg.Sections() {
		if section.Name() == "DEFAULT" {
			continue
		}
		dirPath := section.Name()
		dbPath := filepath.Join(dirPath, ".db.json")
		baseName := filepath.Base(dirPath)
		hashFilePath := filepath.Join(dirPath, fmt.Sprintf(".%s.json", baseName))
		fmt.Printf("Processing directory: %s\n", dirPath)

		// Load existing .db.json if it exists
		var existingHashes []FileHash
		if _, err := os.Stat(dbPath); err == nil {
			decryptedData, err := decryptFile(key, dbPath)
			if err != nil {
				return fmt.Errorf("failed to decrypt existing .db.json for %s: %v", dirPath, err)
			}
			if err := json.Unmarshal(decryptedData, &existingHashes); err != nil {
				return fmt.Errorf("failed to parse existing .db.json for %s: %v", dirPath, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to check .db.json existence for %s: %v", dirPath, err)
		}

		// Update the hash map
		hashMap := make(map[string]string)
		for _, h := range existingHashes {
			hashMap[h.Path] = h.Hash
		}

		for _, key := range section.Keys() {
			filePath := filepath.Join(dirPath, key.Name())
			hashValue := key.Value()

			if hashValue == "REMOVE" {
				if _, exists := hashMap[filePath]; exists {
					delete(hashMap, filePath)
					fmt.Printf("Removed file from hash database: %s\n", filePath)
				}
			} else {
				hashMap[filePath] = hashValue
				fmt.Printf("Updated/Added file in hash database: %s\n", filePath)
			}
		}
		// Create updated .db.json
		var updatedHashes []FileHash
		for path, hash := range hashMap {
			updatedHashes = append(updatedHashes, FileHash{
				Path: path,
				Hash: hash,
			})
		}

		jsonData, err := json.Marshal(updatedHashes)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON for %s: %v", dirPath, err)
		}

		encryptedData, err := encryptFile(key, jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt data for %s: %v", dirPath, err)
		}

		fmt.Printf("Writing updated .db.json to %s\n", dbPath)
		if err := os.WriteFile(dbPath, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write .db.json for %s: %v", dirPath, err)
		}

		// Step 2: Update the corresponding .apps.json
		// Calculate the new hash of the encrypted .db.json
		newDBHash, err := calculateFileHash(dbPath)
		if err != nil {
			return fmt.Errorf("failed to calculate new hash for %s: %v", dbPath, err)
		}
		// Create the updated DBHash structure
		dbHash := DBHash{
			Path: dbPath,
			Hash: newDBHash,
		}
		// Marshal to JSON
		hashJsonData, err := json.MarshalIndent(dbHash, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal hash JSON for %s: %v", hashFilePath, err)
		}

		// Encrypt the new .apps.json content
		encryptedHashData, err := encryptFile(key, hashJsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt hash data for %s: %v", hashFilePath, err)
		}

		// Write the updated .apps.json
		fmt.Printf("Writing updated %s with new .db.json hash\n", hashFilePath)
		if err := os.WriteFile(hashFilePath, encryptedHashData, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %v", hashFilePath, err)
		}
		fmt.Printf("Updated hash database for %s\n", dirPath)
	}
	return nil
}

func opsCommand(imagePath, dbPath, operation string) error {
	key, err := extractKeyFromImage(imagePath)
	if err != nil {
		return fmt.Errorf("failed to extract key: %v", err)
	}

	switch operation {
	case "dec":
		plaintext, err := decryptFile(key, dbPath)
		if err != nil {
			return fmt.Errorf("decryption failed: %v", err)
		}
		// Write decrypted content to a new file with .dec suffix
		outputPath := dbPath + ".dec"
		if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
			return fmt.Errorf("failed to write decrypted file: %v", err)
		}
		fmt.Printf("Decrypted .db.json saved to %s\n", outputPath)

	case "enc":
		// Read the plain JSON file (assuming it's the decrypted version)
		plaintext, err := os.ReadFile(dbPath)
		if err != nil {
			return fmt.Errorf("failed to read file for encryption: %v", err)
		}
		// Validate it's valid JSON
		var temp []FileHash
		if err := json.Unmarshal(plaintext, &temp); err != nil {
			return fmt.Errorf("invalid JSON format: %v", err)
		}
		encryptedData, err := encryptFile(key, plaintext)
		if err != nil {
			return fmt.Errorf("encryption failed: %v", err)
		}
		// Write encrypted content back to the original file
		if err := os.WriteFile(dbPath, encryptedData, 0644); err != nil {
			return fmt.Errorf("failed to write encrypted file: %v", err)
		}
		fmt.Printf("Encrypted .db.json saved to %s\n", dbPath)

	default:
		return fmt.Errorf("invalid operation: %s (must be 'enc' or 'dec')", operation)
	}
	return nil
}

func getCurrentIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "Unknown (error retrieving IP)"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "Unknown (no suitable IP found)"
}

func generatePDFReport(entries []ReportEntry, allValid bool) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "CloudX File Integrity Verification Report")
	pdf.Ln(15)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Date: %s", time.Now().Format(time.RFC1123)))
	pdf.Ln(8)
	pdf.Cell(0, 10, fmt.Sprintf("IP Address: %s", getCurrentIP()))
	pdf.Ln(8)
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown (error retrieving hostname)"
	}
	pdf.Cell(0, 10, fmt.Sprintf("Hostname: %s", hostname))
	pdf.Ln(10)

	for _, entry := range entries {
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(0, 10, fmt.Sprintf("Directory: %s", entry.Directory))
		pdf.Ln(8)

		pdf.SetFont("Arial", "", 12)
		pdf.Cell(0, 10, fmt.Sprintf("Status: %s", entry.Status))
		pdf.Ln(8)

		if len(entry.Details) > 0 {
			pdf.Cell(0, 10, "Verification Details:")
			pdf.Ln(6)
			for _, detail := range entry.Details {
				pdf.MultiCell(0, 6, fmt.Sprintf("- %s", detail), "", "", false)
			}
		}

		if len(entry.NewFiles) > 0 {
			pdf.Ln(4)
			pdf.Cell(0, 10, "New Files Detected:")
			pdf.Ln(6)
			for _, newFile := range entry.NewFiles {
				pdf.MultiCell(0, 6, fmt.Sprintf("- %s", newFile), "", "", false)
			}
		}
		pdf.Ln(10)
	}

	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "Summary")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 12)
	if allValid {
		pdf.Cell(0, 10, "All directories verified successfully - no unauthorized changes or additions")
	} else {
		pdf.Cell(0, 10, "Verification failed - unauthorized changes or additions detected in one or more directories")
	}

	outputPath := fmt.Sprintf("/tmp/file_integrity_report_%s.pdf", time.Now().Format("20060102_150405"))
	return pdf.OutputFileAndClose(outputPath)
}

func cleanupTempFiles() {
	files := []string{"extracted_key.txt"}
	for _, file := range files {
		if err := os.Remove(file); err == nil || os.IsNotExist(err) {
			continue
		} else {
			fmt.Printf("Warning: Failed to remove temporary file %s: %v\n", file, err)
		}
	}
}

func main() {
	// Cleanup temp files on exit
	defer cleanupTempFiles()

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  integrityx verify <image-path>")
		fmt.Println("  integrityx update <image-path> -f <update.ini>")
		fmt.Println("  integrityx ops <image-path> -db <path-of-.db.json> enc|dec")
		return
	}

	command := os.Args[1]

	switch command {
	case "verify":
		if len(os.Args) != 3 {
			fmt.Println("Usage: integrityx verify <image-path>")
			return
		}
		imagePath := os.Args[2]

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

		// Channel to collect results from goroutines
		type Result struct {
			Valid bool
			Entry ReportEntry
			Err   error
		}
		resultChan := make(chan Result, len(directories))
		sem := make(chan struct{}, 2) // Limit to 2 concurrent goroutines

		// Launch goroutines for each directory
		for _, dir := range directories {
			go func(dir string) {
				sem <- struct{}{}        // Acquire semaphore
				defer func() { <-sem }() // Release semaphore
				fmt.Printf("\nVerifying directory: %s (in parallel)\n", dir)
				valid, entry, err := verifyDirectory(key, dir)
				resultChan <- Result{Valid: valid, Entry: entry, Err: err}
			}(dir)
		}

		// Collect results
		var reportEntries []ReportEntry
		allValid := true
		for i := 0; i < len(directories); i++ {
			res := <-resultChan
			if res.Err != nil {
				fmt.Printf("Error verifying %s: %v\n", res.Entry.Directory, res.Err)
				allValid = false
			}
			reportEntries = append(reportEntries, res.Entry)
			if !res.Valid {
				allValid = false
			}
		}
		close(resultChan)
		// for _, dir := range directories {
		// 	fmt.Printf("\nVerifying directory: %s\n", dir)
		// 	valid, entry, err := verifyDirectory(key, dir)
		// 	if err != nil {
		// 		fmt.Printf("Error verifying %s: %v\n", dir, err)
		// 		reportEntries = append(reportEntries, entry)
		// 		allValid = false
		// 		continue
		// 	}
		// 	reportEntries = append(reportEntries, entry)
		// 	if !valid {
		// 		allValid = false
		// 	}
		// }

		if allValid {
			fmt.Println("\nAll directories verified successfully - no unauthorized changes or additions")
		} else {
			fmt.Println("\nVerification failed - unauthorized changes or additions detected in one or more directories")
		}

		if err := generatePDFReport(reportEntries, allValid); err != nil {
			fmt.Println("Error generating PDF report:", err)
		} else {
			fmt.Printf("PDF report saved to /tmp/file_integrity_report_%s.pdf\n", time.Now().Format("20060102_150405"))
		}

	case "update":
		updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
		updateFile := updateCmd.String("f", "", "Path to update.ini file")
		updateCmd.Parse(os.Args[3:])

		if len(os.Args) < 3 || *updateFile == "" {
			fmt.Println("Usage: integrityx update <image-path> -f <update.ini>")
			return
		}

		imagePath := os.Args[2]
		key, err := extractKeyFromImage(imagePath)
		if err != nil {
			fmt.Println("Error extracting key from image:", err)
			return
		}

		cfg, err := ini.Load(*updateFile)
		if err != nil {
			fmt.Println("Error loading update.ini:", err)
			return
		}

		sections := cfg.Sections()
		resultChan := make(chan error, len(sections)-1) // -1 to exclude DEFAULT
		for _, section := range sections {
			if section.Name() == "DEFAULT" {
				continue
			}
			go func(dirPath string) {
				fmt.Printf("Processing directory: %s (in parallel)\n", dirPath)
				err := updateDirectory(key, *updateFile) // Note: this updates all dirs; adjust if needed
				resultChan <- err
			}(section.Name())
		}

		for i := 0; i < len(sections)-1; i++ {
			if err := <-resultChan; err != nil {
				fmt.Println("Error updating directory:", err)
				return
			}
		}
		close(resultChan)
		// if err := updateDirectory(key, *updateFile); err != nil {
		// 	fmt.Println("Error updating directories:", err)
		// 	return
		// }
		fmt.Println("Directory hash databases updated successfully")

	case "ops":
		opsCmd := flag.NewFlagSet("ops", flag.ExitOnError)
		dbPath := opsCmd.String("db", "", "Path to .db.json file")
		opsCmd.Parse(os.Args[3:])

		if len(os.Args) < 5 || *dbPath == "" || (os.Args[len(os.Args)-1] != "enc" && os.Args[len(os.Args)-1] != "dec") {
			fmt.Println("Usage: integrityx ops <image-path> -db <path-of-.db.json> enc|dec")
			return
		}

		imagePath := os.Args[2]
		operation := os.Args[len(os.Args)-1]

		if err := opsCommand(imagePath, *dbPath, operation); err != nil {
			fmt.Println("Error performing ops command:", err)
			return
		}

	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Usage:")
		fmt.Println("  integrityx verify <image-path>")
		fmt.Println("  integrityx update <image-path> -f <update.ini>")
		fmt.Println("  integrityx ops <image-path> -db <path-of-.db.json> enc|dec")
	}
}
