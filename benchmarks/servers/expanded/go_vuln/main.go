package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"

	"github.com/gin-gonic/gin"
)

var key = []byte("secretkeysecretk") // 16 bytes
var iv = []byte("staticivstaticiv")  // 16 bytes

func decryptPaddingOracle(ctB64 string) (string, error) {
	ct, _ := base64.StdEncoding.DecodeString(ctB64)
	block, _ := aes.NewCipher(key)

	// Simplified Padding Oracle simulation for benchmark
	// In real life, this would be a full decryption loop.
	// We leak if the padding is correct or not.
	if len(ct) < block.BlockSize() {
		return "", fmt.Errorf("Padding error: ciphertext too short")
	}

	// Check for a specific byte to simulate a padding error
	if ct[len(ct)-1] == 0x00 {
		return "", fmt.Errorf("Padding error: invalid padding byte")
	}

	return "decrypted content", nil
}

func main() {
	r := gin.Default()
	r.POST("/api/decrypt", func(c *gin.Context) {
		ct := c.PostForm("ciphertext")
		pt, err := decryptPaddingOracle(ct)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"plaintext": pt})
	})
	r.Run(":8081")
}
