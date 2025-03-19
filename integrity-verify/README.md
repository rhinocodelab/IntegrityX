
### Purpose
The program is designed to verify the integrity of a set of files in specified directories on a filesystem (mounted at `/sda1`). It checks whether the original files (as recorded in an encrypted `.db.json` database) remain unchanged by comparing their current hashes against stored hashes. Additionally, it informs the user about new files added to the directories without affecting the core integrity check of the original files. The program ensures the filesystem's integrity by detecting modifications, deletions, or missing files while providing informational updates about new additions.

---

### Key Components
1. **File Hashing**:
   - Uses the SHA-256 algorithm (`crypto/sha256`) to generate unique hashes for files, ensuring even small changes are detectable.

2. **Encryption/Decryption**:
   - Implements AES-GCM (`crypto/aes`, `crypto/cipher`) to decrypt the `.db.json` file, which stores the original file hashes securely.

3. **Steganography**:
   - Utilizes the external `steghide` tool to extract an encryption key hidden in an image, providing a layer of obscurity for key storage.

4. **Filesystem Management**:
   - Includes functions (`remountSDA1RW`, `remountSDA1RO`) to temporarily remount the `/sda1` partition as read-write for verification, then revert to read-only for protection.

5. **Directory Scanning**:
   - Employs `filepath.Walk` to scan directories and detect new files not present in the original database.

6. **Data Structure**:
   - Defines a `FileHash` struct to store file paths and their corresponding hashes, serialized/deserialized via JSON (`encoding/json`).

---

### Main Workflow
The program follows this workflow:
1. **Input Validation**:
   - Checks for a command-line argument specifying the image path containing the hidden encryption key.
   - Exits with usage instructions if not provided.

2. **Key Extraction**:
   - Extracts the AES key from the specified image using `steghide` via `extractKeyFromImage`.

3. **Filesystem Preparation**:
   - Remounts `/sda1` as read-write using `remountSDA1RW`.
   - Defers remounting it as read-only (`remountSDA1RO`) when the program exits.

4. **Directory Verification**:
   - Iterates over predefined directories (`/sda1/data/apps/`, `/sda1/data/basic/`, `/sda1/data/core/`, `/sda1/boot/`):
     - **Decryption**: Decrypts the `.db.json` file in each directory using the extracted key.
     - **Hash Verification**: 
       - Loads stored hashes from `.db.json`.
       - Recalculates current hashes for each listed file.
       - Reports mismatches (modified files) or missing files, setting `allMatch` to `false` if detected.
     - **New File Detection**:
       - Scans the directory for files not in `.db.json`.
       - Reports new files as informational messages without affecting `allMatch`.
     - **Result**: Prints success or failure for each directory based on the integrity of original files.

5. **Summary**:
   - If all directories’ original files are intact (no modifications or missing files), reports overall success.
   - Otherwise, indicates verification failure.

---

### Security Features
1. **Encrypted Hash Storage**:
   - The `.db.json` file containing file hashes is encrypted with AES-GCM, ensuring that an attacker cannot easily read or modify the stored hashes without the key.
   - GCM mode provides both confidentiality and authenticity, preventing tampering with the encrypted data.

2. **Key Concealment via Steganography**:
   - The encryption key is hidden in an image using `steghide`, adding a layer of obscurity. An attacker would need both the image and knowledge of the steganography method to extract the key.

3. **Read-Only Filesystem Protection**:
   - The program remounts `/sda1` as read-only after verification, minimizing the window during which the filesystem is writable and reducing the risk of unauthorized modifications.

4. **Cryptographic Hashing**:
   - SHA-256 is used for file hashing, providing a collision-resistant method to detect any changes to file contents, ensuring high integrity verification reliability.

5. **Error Handling**:
   - Robust error checking throughout (e.g., file reading, decryption, hash calculation) prevents the program from proceeding with invalid data, reducing the risk of false positives or security bypasses.

6. **Nonce Usage in Encryption**:
   - While not directly visible in the verification code (it’s in the encryption phase from the first program), the use of a random nonce with AES-GCM ensures that the same plaintext encrypts differently each time, enhancing security against replay attacks.

---

### Example Scenario
If you modify `/sda1/data/basic/somefile.txt` and add `/sda1/data/basic/newfile.txt`:
- **Output**:
  ```
  Verifying directory: /sda1/data/basic/
  Hash mismatch for /sda1/data/basic/somefile.txt
  Stored: <original_hash>
  Current: <new_hash>
  New file added: /sda1/data/basic/newfile.txt
  Note: New files detected, but this does not affect the integrity check of original files.
  Integrity check failed for original files in /sda1/data/basic/
  ...
  Verification failed for one or more directories' original files
  ```
- **Security**: The mismatch is detected due to SHA-256 sensitivity, and the encrypted `.db.json` ensures the stored hash is trustworthy.

This design makes the program suitable for monitoring critical system files while providing visibility into filesystem changes without overloading the user with unnecessary failures for new files.
