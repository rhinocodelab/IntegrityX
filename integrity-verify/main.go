package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jung-kurt/gofpdf"
)

type FileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

// ReportEntry holds verification details for the PDF report
type ReportEntry struct {
	Directory string
	Status    string
	Details   []string
	NewFiles  []string
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

func verifyDirectory(key []byte, dirPath string) (bool, ReportEntry, error) {
	dbPath := filepath.Join(dirPath, ".db.json")
	entry := ReportEntry{Directory: dirPath}

	// Decrypt the hash database
	decryptedData, err := decryptFile(key, dbPath)
	if err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to decrypt .db.json: %v", err))
		return false, entry, err
	}

	// Parse the stored hashes
	var storedHashes []FileHash
	if err := json.Unmarshal(decryptedData, &storedHashes); err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to parse .db.json: %v", err))
		return false, entry, err
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
				detail := fmt.Sprintf("File missing: %s", storedHash.Path)
				fmt.Println(detail)
				entry.Details = append(entry.Details, detail)
				allMatch = false
				continue
			}
			entry.Status = "Error"
			entry.Details = append(entry.Details, fmt.Sprintf("Failed to calculate hash for %s: %v", storedHash.Path, err))
			return false, entry, err
		}

		if currentHash != storedHash.Hash {
			detail := fmt.Sprintf("Hash mismatch for %s\n  Stored: %s\n  Current: %s", storedHash.Path, storedHash.Hash, currentHash)
			fmt.Println(detail)
			entry.Details = append(entry.Details, detail)
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
				entry.NewFiles = append(entry.NewFiles, path)
				newFilesFound = true
			}
		}
		return nil
	})
	if err != nil {
		entry.Status = "Error"
		entry.Details = append(entry.Details, fmt.Sprintf("Failed to scan directory: %v", err))
		return false, entry, err
	}

	if newFilesFound {
		fmt.Println("Note: New files detected, but this does not affect the integrity check of original files.")
	}

	if allMatch {
		entry.Status = "Success"
		fmt.Printf("All original files in %s verified successfully\n", dirPath)
	} else {
		entry.Status = "Failed"
		fmt.Printf("Integrity check failed for original files in %s\n", dirPath)
	}

	return allMatch, entry, nil
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
			pdf.Cell(0, 10, "Details:")
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
		pdf.Cell(0, 10, "All directories' original files verified successfully")
	} else {
		pdf.Cell(0, 10, "Verification failed for one or more directories' original files")
	}

	outputPath := fmt.Sprintf("/tmp/file_integrity_report_%s.pdf", time.Now().Format("20060102_150405"))
	return pdf.OutputFileAndClose(outputPath)
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

	var reportEntries []ReportEntry
	allValid := true
	for _, dir := range directories {
		fmt.Printf("\nVerifying directory: %s\n", dir)
		valid, entry, err := verifyDirectory(key, dir)
		if err != nil {
			fmt.Printf("Error verifying %s: %v\n", dir, err)
			reportEntries = append(reportEntries, entry)
			allValid = false
			continue
		}
		reportEntries = append(reportEntries, entry)
		if !valid {
			allValid = false
		}
	}

	if allValid {
		fmt.Println("\nAll directories' original files verified successfully")
	} else {
		fmt.Println("\nVerification failed for one or more directories' original files")
	}

	// Generate PDF report
	if err := generatePDFReport(reportEntries, allValid); err != nil {
		fmt.Println("Error generating PDF report:", err)
	} else {
		fmt.Printf("PDF report saved to /tmp/file_integrity_report_%s.pdf\n", time.Now().Format("20060102_150405"))
	}
}
