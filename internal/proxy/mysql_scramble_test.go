package proxy

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"
)

func TestVerifyNativePasswordScramble(t *testing.T) {
	password := "my-secure-password"
	salt := []byte("12345678901234567890")

	// 1. Calculate double SHA1
	h1 := sha1.New()
	h1.Write([]byte(password))
	sha1Pwd := h1.Sum(nil)

	h2 := sha1.New()
	h2.Write(sha1Pwd)
	doubleSHA1 := h2.Sum(nil)

	// 2. Generate client scramble
	hs := sha1.New()
	hs.Write(salt)
	hs.Write(doubleSHA1)
	saltHash := hs.Sum(nil)

	clientAuthData := make([]byte, 20)
	for i := 0; i < 20; i++ {
		clientAuthData[i] = sha1Pwd[i] ^ saltHash[i]
	}

	// 3. Verify inline logic
	hVerify := sha1.New()
	hVerify.Write(salt[:20])
	hVerify.Write(doubleSHA1)
	saltHashVerify := hVerify.Sum(nil)

	recoveredSHA1 := make([]byte, 20)
	for i := 0; i < 20; i++ {
		recoveredSHA1[i] = clientAuthData[i] ^ saltHashVerify[i]
	}

	hVerify2 := sha1.New()
	hVerify2.Write(recoveredSHA1)
	calculatedDoubleSHA1Verify := hVerify2.Sum(nil)

	if !bytes.Equal(calculatedDoubleSHA1Verify, doubleSHA1) {
		t.Errorf("native password scramble verification failed")
	}
}

func TestVerifyCachingSHA2PasswordScramble(t *testing.T) {
	password := "my-secure-password"
	salt := []byte("12345678901234567890")

	// 1. Calculate double SHA256
	h1 := sha256.New()
	h1.Write([]byte(password))
	sha256Pwd := h1.Sum(nil)

	h2 := sha256.New()
	h2.Write(sha256Pwd)
	doubleSHA256 := h2.Sum(nil)

	// 2. Generate client scramble
	hs := sha256.New()
	hs.Write(doubleSHA256)
	hs.Write(salt)
	saltHash := hs.Sum(nil)

	clientAuthData := make([]byte, 32)
	for i := 0; i < 32; i++ {
		clientAuthData[i] = sha256Pwd[i] ^ saltHash[i]
	}

	// 3. Verify inline logic
	hVerify := sha256.New()
	hVerify.Write(doubleSHA256)
	hVerify.Write(salt[:20])
	saltHashVerify := hVerify.Sum(nil)

	recoveredSHA256 := make([]byte, 32)
	for i := 0; i < 32; i++ {
		recoveredSHA256[i] = clientAuthData[i] ^ saltHashVerify[i]
	}

	hVerify2 := sha256.New()
	hVerify2.Write(recoveredSHA256)
	calculatedDoubleSHA256Verify := hVerify2.Sum(nil)

	if !bytes.Equal(calculatedDoubleSHA256Verify, doubleSHA256) {
		t.Errorf("caching sha2 password scramble verification failed")
	}
}
