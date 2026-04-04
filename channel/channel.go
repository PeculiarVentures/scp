// Package channel implements SCP11 secure messaging: encrypting and
// MACing command APDUs, and verifying/decrypting response APDUs.
//
// Once an SCP11 session is established (keys derived), every command
// sent to the card goes through this layer:
//
//  1. Pad and encrypt the data field with S-ENC (AES-CBC, IV derived
//     from an encryption counter).
//  2. Compute C-MAC over the modified header + encrypted payload,
//     chaining from the previous MAC.
//  3. Append the MAC (first 8 bytes) to the command data.
//  4. Set CLA bit 2 (0x04) to indicate secure messaging.
//
// Responses are unwrapped in reverse: verify R-MAC, then decrypt.
//
// This implementation follows GP Card Spec v2.3 §10.8 and matches
// the SCP11 state machine defined in GP Card Spec v2.3 Amendment D §10.8.

package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
	"github.com/PeculiarVentures/scp/cmac"
	"github.com/PeculiarVentures/scp/kdf"
)

// SecureChannel holds the session keys and state needed to wrap and
// unwrap APDUs. It is created after a successful SCP11 key agreement
// and discarded when the session ends.
type SecureChannel struct {
	keys       *kdf.SessionKeys
	encCounter uint32
	macChain   []byte // 16-byte MAC chaining value

	// SecurityLevel controls which protections are applied.
	// GP defines these as bit flags in the "i" parameter.
	SecurityLevel SecurityLevel

	// MACSize is the truncated MAC length appended to APDUs.
	// S8 mode = 8 bytes (default), S16 mode = 16 bytes.
	MACSize int
}

// SecurityLevel defines which secure messaging operations to apply.
type SecurityLevel uint8

const (
	LevelCMAC        SecurityLevel = 0x01 // Command MAC
	LevelCDEC        SecurityLevel = 0x02 // Command decryption (encryption)
	LevelRMAC        SecurityLevel = 0x10 // Response MAC
	LevelRENC        SecurityLevel = 0x20 // Response encryption
	LevelFull        SecurityLevel = LevelCMAC | LevelCDEC | LevelRMAC | LevelRENC
	MACLen                         = 8 // Truncated MAC length appended to APDUs
	FullMACLen                     = 16
)

// Byte encodes the SecurityLevel as the P1 byte for EXTERNAL AUTHENTICATE.
func (sl SecurityLevel) Byte() byte {
	return byte(sl)
}

// New creates a SecureChannel from derived session keys (S8 mode, 8-byte MAC).
func New(keys *kdf.SessionKeys, level SecurityLevel) *SecureChannel {
	return NewWithMACSize(keys, level, MACLen)
}

// NewS16 creates a SecureChannel with S16 mode (16-byte MAC).
func NewS16(keys *kdf.SessionKeys, level SecurityLevel) *SecureChannel {
	return NewWithMACSize(keys, level, FullMACLen)
}

// NewWithMACSize creates a SecureChannel with a specific MAC truncation length.
func NewWithMACSize(keys *kdf.SessionKeys, level SecurityLevel, macSize int) *SecureChannel {
	macChain := make([]byte, 16)
	if keys.MACChain != nil {
		copy(macChain, keys.MACChain)
	}
	return &SecureChannel{
		keys:          keys,
		encCounter:    1,
		macChain:      macChain,
		SecurityLevel: level,
		MACSize:       macSize,
	}
}

// Wrap applies SCP11 secure messaging to a command APDU.
// Returns a new command with encrypted data, appended MAC, and
// the secure messaging CLA bit set.
func (sc *SecureChannel) Wrap(cmd *apdu.Command) (*apdu.Command, error) {
	if sc.keys == nil {
		return nil, errors.New("secure channel not initialized")
	}

	// Start with the plaintext data (may be nil for data-less commands).
	payload := cmd.Data

	// Step 1: Encrypt the payload if C-DEC is active.
	// GP §5.3.2: Empty data skips encryption but
	// increments the counter.
	if sc.SecurityLevel&LevelCDEC != 0 {
		if len(payload) > 0 {
			encrypted, err := sc.encryptPayload(payload)
			if err != nil {
				return nil, fmt.Errorf("encrypt payload: %w", err)
			}
			payload = encrypted
		} else {
			sc.encCounter++
		}
	}

	// Step 2: Compute C-MAC.
	// GP §5.3.2: MAC chaining — each MAC uses the previous full MAC as IV.
	// The MAC input is: macChain || CLA' || INS || P1 || P2 || Lc' || encrypted_data
	// CMAC handles its own internal padding per NIST 800-38B — we must NOT
	// add ISO 9797-1 padding externally.
	if sc.SecurityLevel&LevelCMAC != 0 {
		newCLA := cmd.CLA | 0x04 // Set secure messaging bit

		// Lc will be: len(payload) + sc.MACSize (for the MAC that will be appended)
		lc := len(payload) + sc.MACSize

		// Build MAC input: macChain || APDU_header || payload
		
		var macInput []byte
		macInput = append(macInput, sc.macChain...)
		macInput = append(macInput, newCLA, cmd.INS, cmd.P1, cmd.P2)
		macInput = append(macInput, byte(lc))
		macInput = append(macInput, payload...)

		mac, err := cmac.AESCMAC(sc.keys.SMAC, macInput)
		if err != nil {
			return nil, fmt.Errorf("compute C-MAC: %w", err)
		}

		// Update MAC chain for next command.
		sc.macChain = mac

		// Build the wrapped command: encrypted_data || truncated_mac
		var wrappedData []byte
		wrappedData = append(wrappedData, payload...)
		wrappedData = append(wrappedData, mac[:sc.MACSize]...)

		return &apdu.Command{
			CLA:            newCLA,
			INS:            cmd.INS,
			P1:             cmd.P1,
			P2:             cmd.P2,
			Data:           wrappedData,
			Le:             cmd.Le,
			ExtendedLength: cmd.ExtendedLength || len(wrappedData) > 255,
		}, nil
	}

	// No MAC, just return with potentially encrypted payload.
	return &apdu.Command{
		CLA:            cmd.CLA,
		INS:            cmd.INS,
		P1:             cmd.P1,
		P2:             cmd.P2,
		Data:           payload,
		Le:             cmd.Le,
		ExtendedLength: cmd.ExtendedLength || len(payload) > 255,
	}, nil
}

// Unwrap verifies and decrypts a response APDU from the card.
func (sc *SecureChannel) Unwrap(resp *apdu.Response) (*apdu.Response, error) {
	if sc.keys == nil {
		return nil, errors.New("secure channel not initialized")
	}

	data := resp.Data

	// Step 1: Verify R-MAC if active.
	if sc.SecurityLevel&LevelRMAC != 0 {
		if len(data) < sc.MACSize {
			return nil, errors.New("response too short for R-MAC")
		}

		// R-MAC is the last 8 bytes of the response data.
		receivedMAC := data[len(data)-sc.MACSize:]
		responseData := data[:len(data)-sc.MACSize]

		// R-MAC input: mac_chain || response_data || SW1 || SW2
		// R-MAC input: macChain || responseData || SW1 || SW2
		var macInput []byte
		macInput = append(macInput, sc.macChain...)
		macInput = append(macInput, responseData...)
		macInput = append(macInput, resp.SW1, resp.SW2)

		expectedMAC, err := cmac.AESCMAC(sc.keys.SRMAC, macInput)
		if err != nil {
			return nil, fmt.Errorf("compute R-MAC: %w", err)
		}

		if !constantTimeEqual(expectedMAC[:MACLen], receivedMAC) {
			return nil, errors.New("R-MAC verification failed: response may be tampered")
		}

		data = responseData
	}

	// Step 2: Decrypt response data if R-ENC is active and there's data.
	if sc.SecurityLevel&LevelRENC != 0 && len(data) > 0 {
		decrypted, err := sc.decryptPayload(data)
		if err != nil {
			return nil, fmt.Errorf("decrypt response: %w", err)
		}
		data = decrypted
	}

	return &apdu.Response{
		Data: data,
		SW1:  resp.SW1,
		SW2:  resp.SW2,
	}, nil
}

// encryptPayload encrypts command data using AES-CBC with an IV derived
// from the encryption counter and S-ENC key.
func (sc *SecureChannel) encryptPayload(data []byte) ([]byte, error) {
	iv, err := sc.deriveIV()
	if err != nil {
		return nil, err
	}
	sc.encCounter++

	block, err := aes.NewCipher(sc.keys.SENC)
	if err != nil {
		return nil, err
	}

	// Pad to AES block boundary.
	padded := kdf.Pad(data, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	return encrypted, nil
}

// decryptPayload decrypts response data using AES-CBC.
func (sc *SecureChannel) decryptPayload(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data not block-aligned: %d bytes", len(data))
	}

	// For response decryption, the IV is derived the same way as for
	// encryption but using the response counter value.
	iv, err := sc.deriveResponseIV()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sc.keys.SENC)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	// Remove padding.
	return kdf.Unpad(decrypted)
}

// deriveIV builds the command encryption IV by encrypting the counter
// with S-ENC. GP SCP03 §6.2.2 / SCP11 §5.3.2:
//   AES-ECB(SENC, 00...00 || counter)  — no 0x80 prefix for commands
func (sc *SecureChannel) deriveIV() ([]byte, error) {
	block, err := aes.NewCipher(sc.keys.SENC)
	if err != nil {
		return nil, err
	}

	// Command IV: 12 bytes of 0x00 || 4-byte big-endian counter
	// No prefix byte — commands use all-zero prefix.
	var counterBlock [16]byte
	binary.BigEndian.PutUint32(counterBlock[12:], sc.encCounter)

	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, counterBlock[:])
	return iv, nil
}

// deriveResponseIV builds the response decryption IV.
// Response IV uses encCounter - 1 (matching the preceding encrypt):
//   AES-ECB(SENC, 80 00...00 || (encCounter-1))
// This gets the IV matching the preceding encrypt call.
func (sc *SecureChannel) deriveResponseIV() ([]byte, error) {
	block, err := aes.NewCipher(sc.keys.SENC)
	if err != nil {
		return nil, err
	}

	var counterBlock [16]byte
	counterBlock[0] = 0x80 // Response IV uses 0x80 prefix
	binary.BigEndian.PutUint32(counterBlock[12:], sc.encCounter-1)

	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, counterBlock[:])
	return iv, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// --- Card-side helpers (used by mock card and test harnesses) ---

// ExportMACChain returns a copy of the current MAC chaining value.
func (sc *SecureChannel) ExportMACChain() []byte {
	out := make([]byte, len(sc.macChain))
	copy(out, sc.macChain)
	return out
}

// SetMACChain updates the MAC chaining value (used by card-side after
// verifying a C-MAC).
func (sc *SecureChannel) SetMACChain(mac []byte) {
	copy(sc.macChain, mac)
}

// DecryptCommand decrypts a command payload using the current encryption
// counter and S-ENC key. This is the card-side counterpart to encryptPayload.
// The card uses the raw counter (no 0x80 prefix) for command decryption,
// matching the host's command encryption IV.
func (sc *SecureChannel) DecryptCommand(data []byte) ([]byte, error) {
	if len(data) == 0 {
		sc.encCounter++
		return nil, nil
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data not block-aligned: %d bytes", len(data))
	}

	// Command decryption IV: same as host's command encryption IV.
	// AES-ECB(SENC, 0x00...00 || counter)
	block, err := aes.NewCipher(sc.keys.SENC)
	if err != nil {
		return nil, err
	}

	var counterBlock [16]byte
	binary.BigEndian.PutUint32(counterBlock[12:], sc.encCounter)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, counterBlock[:])

	sc.encCounter++

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	return kdf.Unpad(decrypted)
}

// WrapResponse encrypts response data and appends R-MAC. This is the
// card-side counterpart to the host's Unwrap.
func (sc *SecureChannel) WrapResponse(resp *apdu.Response) (*apdu.Response, error) {
	data := resp.Data

	// Encrypt response data if non-empty.
	if sc.SecurityLevel&LevelRENC != 0 && len(data) > 0 {
		block, err := aes.NewCipher(sc.keys.SENC)
		if err != nil {
			return nil, err
		}

		// Response encryption IV: AES-ECB(SENC, 0x80 || 0x00...00 || (counter-1))
		var counterBlock [16]byte
		counterBlock[0] = 0x80
		binary.BigEndian.PutUint32(counterBlock[12:], sc.encCounter-1)
		iv := make([]byte, aes.BlockSize)
		block.Encrypt(iv, counterBlock[:])

		padded := kdf.Pad(data, aes.BlockSize)
		mode := cipher.NewCBCEncrypter(block, iv)
		encrypted := make([]byte, len(padded))
		mode.CryptBlocks(encrypted, padded)
		data = encrypted
	}

	// Compute R-MAC.
	if sc.SecurityLevel&LevelRMAC != 0 {
		var macInput []byte
		macInput = append(macInput, sc.macChain...)
		macInput = append(macInput, data...)
		macInput = append(macInput, resp.SW1, resp.SW2)

		mac, err := cmac.AESCMAC(sc.keys.SRMAC, macInput)
		if err != nil {
			return nil, err
		}

		var wrappedData []byte
		wrappedData = append(wrappedData, data...)
		wrappedData = append(wrappedData, mac[:sc.MACSize]...)

		return &apdu.Response{Data: wrappedData, SW1: resp.SW1, SW2: resp.SW2}, nil
	}

	return &apdu.Response{Data: data, SW1: resp.SW1, SW2: resp.SW2}, nil
}
