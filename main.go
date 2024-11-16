package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath           = "pgp-mfa.db"
	challengeCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/\\'\"!@#$%^&*()[]{}<>?,.;:"
)

var (
	commands = map[string]func(args []string) error{
		"help":      help,
		"import":    importKey,
		"challenge": challenge,
	}
	db *sql.DB

	ChallengeSolveTime = time.Duration(time.Minute * 1)

	// Key related errors
	ErrKeyPriv         = errors.New("key is private, only public keys are accepted")
	ErrKeyExp          = errors.New("key has expired, cannot import")
	ErrFailedRead      = errors.New("failed to read key")
	ErrPubKeyFail      = errors.New("failed to get public key")
	ErrOpenFailed      = errors.New("failed to open key file")
	ErrAlreadyImported = errors.New("key already imported")

	// Challenge related errors
	ErrChallengeLength = errors.New("challenge length must be a power of two between 1 and 512")
	ErrChallengePow    = errors.New("challenge length must be a power of two")
)

func init() {
	var err error

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	db, err = sql.Open("sqlite3", "file:"+dbPath)
	if err != nil {
		log.Fatalf("failed to open database %s: %v", dbPath, err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys (
		fingerprint VARCHAR(40) NOT NULL PRIMARY KEY,
		pub_key BLOB NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatalf("failed to create table: %v", err)
	}
}

func help(args []string) error {
	fmt.Println("usage: pgp-mfa <command> [args...]")
	fmt.Println("commands:")
	fmt.Println("\timport <key-file> # armored / binary format accepted, - for stdin")
	fmt.Println("\tchallenge [key-id]    # if no key-id is provided, you'll be prompted to select one")
	return nil
}

func openKey(keyFile string) (*os.File, error) {
	if keyFile == "-" {
		return os.Stdin, nil
	}
	return os.Open(keyFile)
}

func importKey(args []string) error {
	if len(args) != 1 {
		fmt.Println("usage: pgp-mfa import <key-file>")
		os.Exit(1)
	}

	keyFile, err := openKey(args[0])
	if err != nil {
		return ErrOpenFailed
	}
	defer keyFile.Close()
	key, err := crypto.NewKeyFromReader(keyFile)
	if err != nil {
		return ErrFailedRead
	}
	bytes, err := key.GetPublicKey()
	if err != nil {
		return ErrPubKeyFail
	}
	if key.IsPrivate() {
		return ErrKeyPriv
	}
	if key.IsExpired(time.Now().Unix()) {
		return ErrKeyExp
	}
	log.Printf("importing key: %s\n", key.GetFingerprint())
	_, err = db.Exec(`INSERT INTO keys (fingerprint, pub_key, created_at) VALUES (?, ?, ?)`,
		key.GetFingerprint(),
		bytes,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("key import error: %v", err)
	}
	log.Println("key imported successfully!")
	return nil
}

func getKey(fingerprint string) (*crypto.Key, error) {
	// Non interactive mode, we got a fingerprint passed
	if len(fingerprint) > 0 {
		row, err := db.Query(`SELECT pub_key FROM keys WHERE fingerprint = ?`, strings.ToLower(fingerprint))
		if err != nil {
			return nil, fmt.Errorf("failed to query key: %v", err)
		}
		defer row.Close()
		var pubKey string
		row.Next()
		err = row.Scan(&pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		key, err := crypto.NewKeyFromReader(bytes.NewReader([]byte(pubKey)))
		return key, err
	}

	// Otherwise interactive mode
	rows, err := db.Query(`SELECT fingerprint, pub_key FROM keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %v", err)
	}
	defer rows.Close()
	var keys []*crypto.Key
	var i int
	for rows.Next() {
		var fingerprint, pubKey string
		err := rows.Scan(&fingerprint, &pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		key, err := crypto.NewKeyFromReader(bytes.NewReader([]byte(pubKey)))
		if err != nil {
			return nil, fmt.Errorf("failed to parse key: %v", err)
		}
		keys = append(keys, key)
		fmt.Printf("[%d]: %s\n", i, fingerprint)
		i++
	}

	// Prompt user to select a key
	fmt.Print("select a key: ")
	var choice int
	if _, err := fmt.Scanf("%d", &choice); err != nil {
		return nil, fmt.Errorf("failed to read choice: %v", err)
	}
	if choice < 0 || choice >= len(keys) {
		return nil, errors.New("invalid choice")
	}
	return keys[choice], nil
}

func generateChallenge(length int) ([]byte, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %v", err)
	}
	for i := 0; i < length; i++ {
		buffer[i] = challengeCharset[buffer[i]%byte(len(challengeCharset))]
	}
	return buffer, nil
}

func encryptChallenge(key *crypto.Key, challenge []byte) ([]byte, string, error) {
	pgpCtx, err := crypto.PGP().Encryption().Recipient(key).New()
	if err != nil {
		return nil, "", fmt.Errorf("failed to create pgp context: %v", err)
	}
	encrypted, err := pgpCtx.Encrypt(challenge)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt challenge: %v", err)
	}
	armored, err := encrypted.Armor()
	if err != nil {
		return nil, "", fmt.Errorf("failed to armor challenge: %v", err)
	}
	return encrypted.Bytes(), armored, nil
}

func challenge(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: pgp-mfa challenge <length> [key-id]")
	}
	length, _ := strconv.Atoi(args[0])
	if length <= 0 || length > 512 {
		return ErrChallengeLength
	}
	if (length & (length - 1)) != 0 {
		return ErrChallengePow
	}
	fingerprint := ""
	if len(args) > 1 {
		fingerprint = args[1]
	}
	selectedKey, err := getKey(fingerprint)
	if err != nil {
		return err
	}

	challengeBytes, err := generateChallenge(length)
	if err != nil {
		return err
	}
	_, armored, err := encryptChallenge(selectedKey, challengeBytes)
	if err != nil {
		return err
	}
	exp := time.Now().Add(ChallengeSolveTime)
	tempFile, err := os.CreateTemp("", "pgp-mfa-challenge-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	writer := io.MultiWriter(tempFile, os.Stdout)
	_, err = writer.Write([]byte(armored + "\n"))
	if err == nil { // if writing in the tempfile succeeded, we can print the solve command
		fmt.Println("solve with: gpg -dq --batch <", tempFile.Name())
	}
	fmt.Println("challenge will expire at", exp.Format(time.RFC3339))

	defer func() {
		os.Remove(tempFile.Name())
	}()

	// Read input from stdin
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("enter your solution: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %v", err)
		}
		if len(input) == 0 {
			continue
		}
		// Check if the challenge has expired
		if exp.Before(time.Now()) {
			return errors.New("challenge has expired")
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(input)), challengeBytes) == 1 {
			fmt.Println("challenge solved!")
			break
		} else {
			fmt.Println("incorrect!")
		}
	}
	return nil
}

func main() {
	defer db.Close()
	if len(os.Args) < 2 {
		fmt.Println("usage: pgp-mfa <command> [args...], use 'pgp-mfa help' for more info")
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	fn, ok := commands[cmd]
	if !ok {
		fmt.Printf("unknown command '%s'\n", cmd)
		help(nil)
		os.Exit(1)
	}
	err := fn(args)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
}
