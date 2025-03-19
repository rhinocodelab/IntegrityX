
# IntegrityX - File Integrity Verification Tool

## Purpose

`IntegrityX` is a command-line tool designed to ensure the integrity of files in specified directories on a Linux system, particularly for critical system directories mounted on `/sda1`. It achieves this by maintaining an encrypted database (`.db.json`) of file hashes and providing commands to update and verify these hashes against the actual files on disk. The tool is intended for system administrators or security professionals who need to detect unauthorized changes, additions, or deletions in protected directories.

Key purposes:
- **Monitor File Integrity**: Detect modifications, new files, or missing files in critical directories.
- **Secure Hash Storage**: Store file hashes in an encrypted format to prevent tampering.
- **Controlled Updates**: Allow explicit updates to the hash database via a configuration file (`update.ini`).
- **Operational Flexibility**: Provide utilities to manually encrypt/decrypt the hash database for inspection or modification.

## Key Components

1. **Commands**:
   - `verify`: Checks the integrity of files in predefined directories against their stored hashes.
   - `update`: Updates the `.db.json` hash database based on an `update.ini` file.
   - `ops`: Encrypts or decrypts a `.db.json` file for manual inspection or modification.

2. **Configuration File (`update.ini`)**:
   - An INI-formatted file specifying directories and file hashes to update in `.db.json`.
   - Supports adding new files, updating existing file hashes, and removing file entries.
   - **Format**:
     - Sections are directory paths (e.g., `[/sda1/data/apps/]`) enclosed in square brackets.
     - Keys are file names (relative to the section’s directory).
     - Values are either SHA-256 hashes (64 hexadecimal characters) or the keyword `REMOVE` to delete an entry.
   - **Example `update.ini`**:
   ```
   [/sda1/data/apps/]
   file1.txt = 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
   test.sq = abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
   oldfile.sq = REMOVE

   [/sda1/data/core/]
   core.sq = fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
   ```

3. **Hash Database (`.db.json`)**:
   - An encrypted JSON file stored in each monitored directory (e.g., `/sda1/data/apps/.db.json`).
   - Contains an array of objects with `path` (absolute file path) and `hash` (SHA-256 hash).

4. **Encryption Key**:
   - Extracted from a steganographic image (e.g., `/sda1/data/.gems.jpeg`) using `steghide`.
   - Used to encrypt and decrypt `.db.json` files with AES-GCM.

5. **Dependencies**:
   - Go libraries: `crypto/aes`, `crypto/cipher`, `crypto/sha256`, `encoding/json`, `gopkg.in/ini.v1`, `github.com/jung-kurt/gofpdf`.
   - External tool: `steghide` (for key extraction from images).

## Main Workflow

### 1. Initialization
- An initial `.db.json` is created or updated using the `update` command with an `update.ini` file specifying file paths and their hashes.
- The database is encrypted with a key extracted from an image file.

### 2. Updating the Database
- **Command**: `integrityx update <image-path> -f <update.ini>`
- **Process**:
  1. Mounts `/sda1` as read-write.
  2. Extracts the encryption key from the image.
  3. Loads the existing `.db.json` (if any) and updates it with entries from `update.ini`.
  4. Constructs absolute paths by combining directory paths (from INI sections) with file names.
  5. Encrypts and saves the updated `.db.json`.
  6. Remounts `/sda1` as read-only.

### 3. Verifying Integrity
- **Command**: `integrityx verify <image-path>`
- **Process**:
  1. Mounts `/sda1` as read-write temporarily.
  2. Extracts the encryption key.
  3. For each monitored directory (e.g., `/sda1/data/apps/`):
     - Decrypts `.db.json`.
     - Compares stored hashes with current file hashes.
     - Checks for missing files (in `.db.json` but not on disk).
     - Detects unauthorized new files (on disk but not in `.db.json`).
  4. Generates a PDF report with verification results.
  5. Remounts `/sda1` as read-only.

### 4. Manual Operations
- **Command**: `integrityx ops <image-path> -db <path-of-.db.json> enc|dec`
- **Decrypt**: Saves the decrypted JSON to `<path-of-.db.json>.dec`.
- **Encrypt**: Encrypts a plain JSON file and overwrites the original `.db.json`.

## Security Features

1. **Encrypted Hash Database**:
   - `.db.json` is encrypted using AES-GCM with a key hidden in an image, preventing unauthorized access or tampering.

2. **Steganographic Key Storage**:
   - The encryption key is embedded in an image file (e.g., `.gems.jpeg`) and extracted using `steghide`, adding a layer of obscurity.

3. **Controlled Updates**:
   - Only files explicitly listed in `update.ini` are added, updated, or removed from `.db.json`, preventing automatic inclusion of unauthorized files.

4. **Read-Only Filesystem Protection**:
   - `/sda1` is remounted as read-write only during updates or verification, then reverted to read-only, minimizing the window for unauthorized modifications.

5. **Integrity Verification**:
   - Uses SHA-256 hashes to detect any changes in file contents.
   - Reports missing files, hash mismatches, and unauthorized new files.

## Example Scenario

### Scenario: Adding and Verifying a New File

**Objective**: Add a new file `test.sq` to `/sda1/data/apps/` and ensure it’s recognized by the integrity check.

#### Step 1: Add the File
- Place `test.sq` in `/sda1/data/apps/`.
- Calculate its SHA-256 hash:
  ```bash
  sha256sum /sda1/data/apps/test.sq
  # Output: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  /sda1/data/apps/test.sq
  ```

#### Step 2: Update the Database
- Create or edit `/tmp/update.ini`:
  ```
  [/sda1/data/apps/]
  test.sq = abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
  ```
- Run the update command:
  ```bash
  integrityx update /sda1/data/.gems.jpeg -f /tmp/update.ini
  ```
- **Output**:
  ```
  Starting directory update process
  Remounting /sda1 as read-write
  Loading update file: /tmp/update.ini
  Processing directory: /sda1/data/apps/
  Updated/Added file in hash database: /sda1/data/apps/test.sq
  Encrypting data
  Writing updated .db.json to /sda1/data/apps/.db.json
  Updated hash database for /sda1/data/apps/
  Remounting /sda1 as read-only
  Directory hash databases updated successfully
  ```

#### Step 3: Verify Integrity
- Run the verify command:
  ```bash
  integrityx verify /sda1/data/.gems.jpeg
  ```
- **Output** (assuming no other issues):
  ```
  Verifying directory: /sda1/data/apps/
  All files in /sda1/data/apps/ verified successfully - no unauthorized changes or additions
  ...
  All directories verified successfully - no unauthorized changes or additions
  PDF report saved to /tmp/file_integrity_report_<timestamp>.pdf
  ```

#### Step 4: Inspect `.db.json` (Optional)
- Decrypt to verify the content:
  ```bash
  integrityx ops /sda1/data/.gems.jpeg -db /sda1/data/apps/.db.json dec
  ```
- Check `/sda1/data/apps/.db.json.dec`:
  ```json
  [
      {
          "path": "/sda1/data/apps/test.sq",
          "hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      }
  ]
  ```

### What Happens Without Update?
- If `test.sq` is added to `/sda1/data/apps/` but not included in `update.ini`, verification fails:
  ```
  Verifying directory: /sda1/data/apps/
  Unauthorized new file detected: /sda1/data/apps/test.sq
  Integrity check failed for /sda1/data/apps/
  ```

## Installation

1. **Install Dependencies**:
   - Install Go: `sudo apt install golang`
   - Install `steghide`: `sudo apt install steghide`
   - Install Go libraries:
     ```bash
     go get gopkg.in/ini.v1
     go get github.com/jung-kurt/gofpdf
     ```

2. **Build the Tool**:
   ```bash
   go build -o integrityx main.go
   ```

3. **Prepare Key Image**:
   - Embed an encryption key in an image using `steghide`:
     ```bash
     echo "mysecretkey" > key.txt
     steghide embed -cf /sda1/data/.gems.jpeg -ef key.txt -p ""
     ```

## Usage

```bash
# Verify integrity
integrityx verify /sda1/data/.gems.jpeg

# Update hash database
integrityx update /sda1/data/.gems.jpeg -f /tmp/update.ini

# Decrypt .db.json
integrityx ops /sda1/data/.gems.jpeg -db /sda1/data/apps/.db.json dec

# Encrypt .db.json
integrityx ops /sda1/data/.gems.jpeg -db /sda1/data/apps/.db.json enc
