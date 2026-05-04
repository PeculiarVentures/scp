package mockcard

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/scp/apdu"
)

// PIV management-key algorithm bytes; mirrored from piv.AlgoMgmt*
// rather than imported to avoid a dependency on the piv package
// from mockcard. Identical numeric values per NIST SP 800-73-4
// Part 1 Table 4.
const (
	mockPIVAlgo3DES   byte = 0x03
	mockPIVAlgoAES128 byte = 0x08
	mockPIVAlgoAES192 byte = 0x0A
	mockPIVAlgoAES256 byte = 0x0C
)

// handlePIVMgmtAuth implements the two-step PIV management-key
// mutual-auth flow against c.PIVMgmtKey / c.PIVMgmtKeyAlgo. Called
// from dispatchINS for INS=0x87, P2=0x9B, when PIVMgmtKey is set.
//
// Step 1 input:  7C 02 80 00            (request witness)
// Step 1 output: 7C LL 80 LL <enc_witness>
//
// Step 2 input:  7C LL 80 LL <plain_witness> 81 LL <host_challenge>
// Step 2 output: 7C LL 82 LL <enc_host_challenge>
//
// The mock dispatches step 1 vs step 2 by inspecting the inner TLV
// shape: empty 80 means step 1, 80 carrying bytes means step 2.
func (c *Card) handlePIVMgmtAuth(cmd *apdu.Command) (*apdu.Response, error) {
	if cmd.P1 != c.PIVMgmtKeyAlgo {
		// Algorithm in the APDU must match what the mock is
		// configured for; a mismatch is the same situation as
		// "card uses different algorithm than host configured."
		return mkSW(0x6A86), nil
	}
	template, err := mockFindTLV(cmd.Data, 0x7C)
	if err != nil {
		return mkSW(0x6A80), nil
	}
	witnessTLV, err := mockFindTLV(template, 0x80)
	if err != nil {
		return mkSW(0x6A80), nil
	}

	bs, err := mockBlockSize(c.PIVMgmtKeyAlgo)
	if err != nil {
		return mkSW(0x6A86), nil
	}

	if len(witnessTLV) == 0 {
		// Step 1: generate witness, encrypt, return.
		w := make([]byte, bs)
		if _, err := rand.Read(w); err != nil {
			return mkSW(0x6F00), nil
		}
		c.pivMgmtAuthWitness = w
		enc, err := mockBlockEncrypt(c.PIVMgmtKey, w, c.PIVMgmtKeyAlgo)
		if err != nil {
			return mkSW(0x6F00), nil
		}
		return &apdu.Response{
			Data: append([]byte{0x7C, byte(2 + len(enc)), 0x80, byte(len(enc))}, enc...),
			SW1:  0x90, SW2: 0x00,
		}, nil
	}

	// Step 2: verify host's decrypted witness equals what we generated.
	if c.pivMgmtAuthWitness == nil {
		// Step 2 without a prior step 1 — fail closed.
		return mkSW(0x6985), nil
	}
	if !bytes.Equal(witnessTLV, c.pivMgmtAuthWitness) {
		// Host doesn't possess the key; clear stored witness so a
		// retry must redo step 1.
		c.pivMgmtAuthWitness = nil
		return mkSW(0x6982), nil
	}
	c.pivMgmtAuthWitness = nil

	// Encrypt the host's challenge to prove we possess the key too.
	hostChallenge, err := mockFindTLV(template, 0x81)
	if err != nil {
		return mkSW(0x6A80), nil
	}
	if len(hostChallenge) != bs {
		return mkSW(0x6A80), nil
	}
	encChallenge, err := mockBlockEncrypt(c.PIVMgmtKey, hostChallenge, c.PIVMgmtKeyAlgo)
	if err != nil {
		return mkSW(0x6F00), nil
	}
	return &apdu.Response{
		Data: append([]byte{0x7C, byte(2 + len(encChallenge)), 0x82, byte(len(encChallenge))}, encChallenge...),
		SW1:  0x90, SW2: 0x00,
	}, nil
}

func mockBlockEncrypt(key, block []byte, algorithm byte) ([]byte, error) {
	c, err := mockNewMgmtCipher(key, algorithm)
	if err != nil {
		return nil, err
	}
	if len(block) != c.BlockSize() {
		return nil, fmt.Errorf("block length %d != cipher block size %d", len(block), c.BlockSize())
	}
	out := make([]byte, c.BlockSize())
	c.Encrypt(out, block)
	return out, nil
}

func mockNewMgmtCipher(key []byte, algorithm byte) (cipher.Block, error) {
	switch algorithm {
	case mockPIVAlgo3DES:
		if len(key) != 24 {
			return nil, fmt.Errorf("3DES key length %d != 24", len(key))
		}
		return des.NewTripleDESCipher(key)
	case mockPIVAlgoAES128, mockPIVAlgoAES192, mockPIVAlgoAES256:
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported PIV management-key algorithm 0x%02X", algorithm)
	}
}

func mockBlockSize(algorithm byte) (int, error) {
	switch algorithm {
	case mockPIVAlgo3DES:
		return 8, nil
	case mockPIVAlgoAES128, mockPIVAlgoAES192, mockPIVAlgoAES256:
		return 16, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm 0x%02X", algorithm)
	}
}

// mockFindTLV is the same shape as piv.findTLV — a tiny TLV walker
// that handles the short / 0x81 / 0x82 length encodings of
// ISO 7816-4 §5.2.2. Duplicated here to keep mockcard from
// importing piv (which would create a cycle with piv's own tests
// that use mockcard).
func mockFindTLV(buf []byte, tag byte) ([]byte, error) {
	for i := 0; i < len(buf); {
		if i >= len(buf) {
			break
		}
		t := buf[i]
		i++
		if i >= len(buf) {
			return nil, errors.New("truncated TLV: no length byte")
		}
		var L int
		switch {
		case buf[i] < 0x80:
			L = int(buf[i])
			i++
		case buf[i] == 0x81:
			if i+1 >= len(buf) {
				return nil, errors.New("truncated TLV: 0x81 length")
			}
			L = int(buf[i+1])
			i += 2
		case buf[i] == 0x82:
			if i+2 >= len(buf) {
				return nil, errors.New("truncated TLV: 0x82 length")
			}
			L = int(buf[i+1])<<8 | int(buf[i+2])
			i += 3
		default:
			return nil, fmt.Errorf("unsupported TLV length encoding 0x%02X", buf[i])
		}
		if i+L > len(buf) {
			return nil, fmt.Errorf("truncated TLV value (need %d bytes, have %d)", L, len(buf)-i)
		}
		if t == tag {
			return buf[i : i+L], nil
		}
		i += L
	}
	return nil, fmt.Errorf("tag 0x%02X not found", tag)
}
