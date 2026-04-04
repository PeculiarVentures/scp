// Package cmac implements AES-CMAC (NIST SP 800-38B), which is the
// PRF used in SCP03/SCP11 for:
//   - Session key derivation (NIST SP 800-108 KDF)
//   - Command/response MAC computation (C-MAC, R-MAC)
//   - Receipt calculation
package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AESCMAC computes a 16-byte AES-CMAC over the given message.
func AESCMAC(key, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	return computeCMAC(block, message)
}

// AESCMACChain computes AES-CMAC with an initial chaining value (IV).
// This is used for C-MAC chaining in secure messaging where each MAC
// computation chains from the previous MAC output.
func AESCMACChain(key, iv, message []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	return computeCMACWithIV(block, iv, message)
}

func computeCMAC(block cipher.Block, message []byte) ([]byte, error) {
	return computeCMACWithIV(block, make([]byte, aes.BlockSize), message)
}

func computeCMACWithIV(block cipher.Block, iv, message []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}

	k1, k2 := generateSubkeys(block)

	n := (len(message) + aes.BlockSize - 1) / aes.BlockSize
	if n == 0 {
		n = 1
	}

	// Determine if the last block is complete.
	lastBlockComplete := len(message) > 0 && len(message)%aes.BlockSize == 0

	// Process all blocks except the last using CBC-MAC.
	x := make([]byte, aes.BlockSize)
	copy(x, iv)

	for i := 0; i < n-1; i++ {
		offset := i * aes.BlockSize
		for j := 0; j < aes.BlockSize; j++ {
			x[j] ^= message[offset+j]
		}
		block.Encrypt(x, x)
	}

	// Process the last block with subkey.
	lastBlock := make([]byte, aes.BlockSize)
	lastOffset := (n - 1) * aes.BlockSize

	if lastBlockComplete {
		copy(lastBlock, message[lastOffset:])
		for j := 0; j < aes.BlockSize; j++ {
			lastBlock[j] ^= k1[j]
		}
	} else {
		// Partial block: pad with 0x80 || 0x00...
		remaining := len(message) - lastOffset
		if remaining > 0 {
			copy(lastBlock, message[lastOffset:])
		}
		lastBlock[remaining] = 0x80
		for j := 0; j < aes.BlockSize; j++ {
			lastBlock[j] ^= k2[j]
		}
	}

	for j := 0; j < aes.BlockSize; j++ {
		x[j] ^= lastBlock[j]
	}
	block.Encrypt(x, x)

	return x, nil
}

// generateSubkeys derives K1 and K2 from the AES key per NIST 800-38B.
func generateSubkeys(block cipher.Block) (k1, k2 []byte) {
	const rb = 0x87 // Reduction polynomial for GF(2^128)

	// L = AES(K, 0^128)
	l := make([]byte, aes.BlockSize)
	block.Encrypt(l, l)

	k1 = shiftLeft(l)
	if l[0]&0x80 != 0 {
		k1[aes.BlockSize-1] ^= rb
	}

	k2 = shiftLeft(k1)
	if k1[0]&0x80 != 0 {
		k2[aes.BlockSize-1] ^= rb
	}

	return k1, k2
}

// shiftLeft shifts a 16-byte value left by 1 bit.
func shiftLeft(input []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input)-1; i++ {
		output[i] = (input[i] << 1) | (input[i+1] >> 7)
	}
	output[len(input)-1] = input[len(input)-1] << 1
	return output
}
