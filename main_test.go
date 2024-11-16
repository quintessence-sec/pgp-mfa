package main

import (
	"log"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

var (
	ecKey      *crypto.Key
	rsa3072Key *crypto.Key
	rsa4092Key *crypto.Key

	challenge16  = []byte{}
	challenge32  = []byte{}
	challenge64  = []byte{}
	challenge128 = []byte{}
	challenge256 = []byte{}
	challenge512 = []byte{}
	chalMap      = map[int][]byte{
		16:  challenge16,
		32:  challenge32,
		64:  challenge64,
		128: challenge128,
		256: challenge256,
		512: challenge512,
	}
)

func benchmarkChallengeEncryption(b *testing.B, length int, key *crypto.Key) {
	byteRef := chalMap[length]
	for i := 0; i < b.N; i++ {
		_, _, err := encryptChallenge(key, byteRef)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkEd25519_16(b *testing.B) {
	benchmarkChallengeEncryption(b, 16, ecKey)
}

func BenchmarkEd25519_32(b *testing.B) {
	benchmarkChallengeEncryption(b, 32, ecKey)
}

func BenchmarkEd25519_64(b *testing.B) {
	benchmarkChallengeEncryption(b, 64, ecKey)
}

func BenchmarkEd25519_128(b *testing.B) {
	benchmarkChallengeEncryption(b, 128, ecKey)
}

func BenchmarkEd25519_256(b *testing.B) {
	benchmarkChallengeEncryption(b, 256, ecKey)
}

func BenchmarkEd25519_512(b *testing.B) {
	benchmarkChallengeEncryption(b, 512, ecKey)
}

func BenchmarkRsa4092_16(b *testing.B) {
	benchmarkChallengeEncryption(b, 16, rsa4092Key)
}

func BenchmarkRsa4092_32(b *testing.B) {
	benchmarkChallengeEncryption(b, 32, rsa4092Key)
}

func BenchmarkRsa4092_64(b *testing.B) {
	benchmarkChallengeEncryption(b, 64, rsa4092Key)
}

func BenchmarkRsa4092_128(b *testing.B) {
	benchmarkChallengeEncryption(b, 128, rsa4092Key)
}

func BenchmarkRsa4092_256(b *testing.B) {
	benchmarkChallengeEncryption(b, 256, rsa4092Key)
}

func BenchmarkRsa4092_512(b *testing.B) {
	benchmarkChallengeEncryption(b, 512, rsa4092Key)
}

func BenchmarkRsa3072_16(b *testing.B) {
	benchmarkChallengeEncryption(b, 16, rsa3072Key)
}

func BenchmarkRsa3072_32(b *testing.B) {
	benchmarkChallengeEncryption(b, 32, rsa3072Key)
}

func BenchmarkRsa3072_64(b *testing.B) {
	benchmarkChallengeEncryption(b, 64, rsa3072Key)
}

func BenchmarkRsa3072_128(b *testing.B) {
	benchmarkChallengeEncryption(b, 128, rsa3072Key)
}

func BenchmarkRsa3072_256(b *testing.B) {
	benchmarkChallengeEncryption(b, 256, rsa3072Key)
}

func BenchmarkRsa3072_512(b *testing.B) {
	benchmarkChallengeEncryption(b, 512, rsa3072Key)
}

func createChallenges(b *testing.B, length int) {
	for i := 0; i < b.N; i++ {
		_, err := generateChallenge(length)
		if err != nil {
			log.Println(err)
			b.Fail()
		}
	}
}

func BenchmarkChallengesGeneration_16(b *testing.B) {
	createChallenges(b, 16)
}

func BenchmarkChallengesGeneration_32(b *testing.B) {
	createChallenges(b, 32)
}

func BenchmarkChallengesGeneration_64(b *testing.B) {
	createChallenges(b, 64)
}

func BenchmarkChallengesGeneration_128(b *testing.B) {
	createChallenges(b, 128)
}

func BenchmarkChallengesGeneration_256(b *testing.B) {
	createChallenges(b, 256)
}

func BenchmarkChallengesGeneration_512(b *testing.B) {
	createChallenges(b, 512)
}

func init() {
	var err error

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Println("preparing challenges bytes")
	bytesPool := make([]byte, 512)
	for i := 0; i < 512; i++ {
		bytesPool[i] = byte(i)
	}
	copy(challenge16, bytesPool)
	copy(challenge32, bytesPool)
	copy(challenge64, bytesPool)
	copy(challenge128, bytesPool)
	copy(challenge256, bytesPool)
	copy(challenge512, bytesPool)

	log.Println("preparing ed25519 key")
	{
		pgpCtx := crypto.PGPWithProfile(profile.Default())
		keygenHandle := pgpCtx.KeyGeneration().AddUserId("test@example.com", "Test User").New()
		ecKey, err = keygenHandle.GenerateKey()
		if err != nil {
			log.Fatalf("failed to generate ed25519 key: %v", err)
		} else {
			key, _ := ecKey.GetPublicKey()
			log.Printf("key fingerprint: %s, key length: %d bytes\n", ecKey.GetFingerprint(), len(key))
		}
	}

	log.Println("preparing rsa3072 key")
	{
		pgpCtx := crypto.PGPWithProfile(profile.RFC4880())
		keygenHandle := pgpCtx.KeyGeneration().AddUserId("test@example.com", "Test User").New()
		rsa3072Key, err = keygenHandle.GenerateKey()
		if err != nil {
			log.Fatalf("failed to generate rsa3072 key: %v", err)
		} else {
			key, _ := rsa3072Key.GetPublicKey()
			log.Printf("key fingerprint: %s, key length: %d bytes\n", rsa3072Key.GetFingerprint(), len(key))
		}
	}

	log.Println("preparing rsa4092 key")
	{
		pgpCtx := crypto.PGPWithProfile(profile.RFC4880())
		keygenHandle := pgpCtx.KeyGeneration().AddUserId("test@example.com", "Test User").New()
		rsa4092Key, err = keygenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
		if err != nil {
			log.Fatalf("failed to generate rsa4092 key: %v", err)
		} else {
			key, _ := rsa4092Key.GetPublicKey()
			log.Printf("key fingerprint: %s, key length: %d bytes\n", rsa4092Key.GetFingerprint(), len(key))
		}
	}
}
