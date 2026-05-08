package gp

import (
	"crypto/sha1" //nolint:gosec // legacy GP LFDBH compatibility (SHA-1 hash is the historical default; SHA-256 is the secure path)
	"crypto/sha256"
	"errors"
	"fmt"
)

// GP §11.6.2 Load File structure tags. The bytes that go on the wire
// during the LOAD command sequence are NOT the raw concatenated CAP
// component stream (which we call the Load File Data Block, LFDB);
// they are an outer TLV wrapper with optional DAP signature blocks
// followed by either a plain LFDB (tag C4) or a ciphered LFDB (tag
// D4). The host streams the wrapped form through LOAD; the card
// strips the wrapper and validates against any DAP signatures
// present.
//
// Pre-fix, this library streamed the raw LFDB through LOAD without
// the C4 wrapper. That worked against the in-tree mockcard (which
// accepted whatever bytes arrived and called it a load) but would
// fail against generic GP cards that strictly enforce the wire shape
// per the Card Spec. This package's BuildPlainLoadFile / ParseLoadFile
// pair is the host-side encoder/decoder for the LOAD wire format.
const (
	// TagDAPBlock is the optional E2 outer DAP block tag. May appear
	// multiple times (one per signing SD). Carries SDAID (4F) and
	// signature (C3).
	TagDAPBlock byte = 0xE2

	// TagSecurityDomainAID is the inner 4F tag inside a DAP block,
	// naming the SD whose key signed the LFDB.
	TagSecurityDomainAID byte = 0x4F

	// TagLoadFileDataBlockSignature is the inner C3 tag inside a DAP
	// block carrying the SD's signature over the LFDB.
	TagLoadFileDataBlockSignature byte = 0xC3

	// TagICV is the optional D3 tag carrying an Initial Chaining
	// Vector for D4-ciphered Load Files. Reserved; not yet supported.
	TagICV byte = 0xD3

	// TagLoadFileDataBlock is the C4 tag wrapping the plaintext
	// Java Card Load File Data Block. This is the typical loading
	// path for non-encrypted, non-DM cards.
	TagLoadFileDataBlock byte = 0xC4

	// TagCipheredLoadFileDataBlock is the D4 tag for an encrypted
	// LFDB. Reserved; not yet supported. Decoder rejects with
	// ErrInvalidLoadFile rather than silently returning unparsed
	// bytes.
	TagCipheredLoadFileDataBlock byte = 0xD4
)

// ErrInvalidLoadFile is returned when a Load File byte stream fails
// structural validation (malformed TLV, missing C4, unsupported D4,
// non-minimal BER length, etc.). Callers can errors.Is on it.
var ErrInvalidLoadFile = errors.New("invalid GlobalPlatform load file")

// LoadFileKind identifies which LFDB form a parsed Load File carries.
// Reserved for forward compatibility — today only LoadFilePlain
// surfaces from ParseLoadFile because D4 is rejected.
type LoadFileKind int

const (
	// LoadFilePlain is the typical case: tag C4 wrapping the
	// concatenated CAP component stream.
	LoadFilePlain LoadFileKind = iota + 1

	// LoadFileCiphered is the D4 case. Reserved; ParseLoadFile
	// rejects until D4 handling is implemented.
	LoadFileCiphered
)

// DAPBlock carries a single E2 outer DAP block: an SD AID (4F) and
// a signature (C3) over the LFDB by that SD's signing key. Multiple
// DAPBlocks may precede the LFDB tag in the wire stream when more
// than one SD requires DAP signing.
//
// The library does not produce signatures; callers integrating with
// DAP-required cards supply DAPBlocks with externally-computed
// signatures. The encode/decode round-trip preserves whatever bytes
// the caller provides without interpreting them.
type DAPBlock struct {
	// SDAID is the 5-16 byte AID of the SD whose key signed the
	// LFDB. Validated against ISO/IEC 7816-5 length bounds at
	// encode time.
	SDAID []byte

	// Signature is the cryptographic signature bytes over the LFDB,
	// formatted per the SD's DAP signing scheme (vendor-specific —
	// the wire layer does not interpret these bytes).
	Signature []byte
}

// LoadFile is the parsed structure of a GP Load File. Today only
// the plain-LFDB shape is populated; CipheredDataBlock and ICV are
// reserved for future D3/D4 support and remain nil.
type LoadFile struct {
	// DAPBlocks are zero or more E2 outer DAP signing blocks that
	// preceded the LFDB on the wire.
	DAPBlocks []DAPBlock

	// DataBlock is the C4-wrapped plaintext LFDB. Non-empty for
	// any LoadFile returned from ParseLoadFile (D4-only is
	// rejected).
	DataBlock []byte

	// CipheredDataBlock is the D4 form. Reserved; always nil today.
	CipheredDataBlock []byte

	// ICV is the D3 initial chaining vector for D4 cipher
	// continuity. Reserved; always nil today.
	ICV []byte
}

// LoadFileOptions controls BuildPlainLoadFile.
type LoadFileOptions struct {
	// DAPBlocks are zero or more DAP signing blocks to prepend to
	// the LFDB on the wire. Encoded as E2 outer wrappers around
	// 4F SDAID + C3 signature.
	DAPBlocks []DAPBlock

	// Ciphered, when true, would request a D4 ciphered LFDB.
	// Reserved; BuildPlainLoadFile rejects with ErrInvalidLoadFile
	// today because D4 ciphering and ICV semantics are not
	// implemented.
	Ciphered bool

	// ICV is the D3 ICV for D4 cipher continuity. Reserved; must be
	// empty today.
	ICV []byte
}

// BuildPlainLoadFile wraps a Java Card Load File Data Block in the
// GlobalPlatform Load File structure that gets streamed through the
// LOAD command sequence per GP Card Spec v2.3.1 §11.6.2.
//
// The lfdb input is the concatenated CAP component byte stream as
// returned by CAPFile.LoadFileDataBlock (or its legacy alias
// CAPFile.LoadImage). It is the same bytes that LoadFileDataBlockHashes
// hashes for the Load File Data Block Hash field of INSTALL [for load].
//
// The returned bytes are the complete wire-format Load File ready
// for chunking across LOAD APDUs:
//
//	[E2 SDAID Signature]*  C4  BER-LENGTH(LFDB)  LFDB
//
// where the optional DAP blocks come first when DAPBlocks is non-empty.
// The caller chunks the result; LOAD APDU boundaries may split the
// stream at any byte position (including inside the BER length, or
// between the C4 tag and the first LFDB byte).
//
// Returns ErrInvalidLoadFile for empty lfdb, opts.Ciphered=true (D4
// reserved), or non-empty opts.ICV (D3 reserved).
func BuildPlainLoadFile(lfdb []byte, opts LoadFileOptions) ([]byte, error) {
	if len(lfdb) == 0 {
		return nil, fmt.Errorf("%w: empty load file data block", ErrInvalidLoadFile)
	}
	if opts.Ciphered {
		return nil, fmt.Errorf("%w: D4 ciphered load file is not implemented", ErrInvalidLoadFile)
	}
	if len(opts.ICV) != 0 {
		return nil, fmt.Errorf("%w: D3 ICV is not implemented", ErrInvalidLoadFile)
	}

	out := make([]byte, 0, len(lfdb)+8)
	for i, dap := range opts.DAPBlocks {
		enc, err := encodeDAPBlock(dap)
		if err != nil {
			return nil, fmt.Errorf("DAP block %d: %w", i, err)
		}
		out = append(out, enc...)
	}

	c4, err := EncodeTLV(TagLoadFileDataBlock, lfdb)
	if err != nil {
		return nil, err
	}
	out = append(out, c4...)
	return out, nil
}

// ParseLoadFile decodes the GlobalPlatform Load File byte stream
// produced by BuildPlainLoadFile (or by an external DAP-signing
// pipeline that produces the same wire shape). Accepts zero or more
// E2 DAP blocks followed by exactly one C4 plain LFDB.
//
// Rejects D3 ICV and D4 ciphered LFDB with ErrInvalidLoadFile —
// these tags are reserved in the spec and not yet implemented in
// this package, and silently accepting them would let callers
// believe an unsupported encoding succeeded.
func ParseLoadFile(stream []byte) (*LoadFile, error) {
	if len(stream) == 0 {
		return nil, fmt.Errorf("%w: empty stream", ErrInvalidLoadFile)
	}

	var lf LoadFile
	rest := stream

	for len(rest) > 0 {
		tag := rest[0]
		value, next, err := readTLVValue(rest)
		if err != nil {
			return nil, err
		}

		switch tag {
		case TagDAPBlock:
			dap, err := parseDAPBlock(value)
			if err != nil {
				return nil, err
			}
			lf.DAPBlocks = append(lf.DAPBlocks, dap)

		case TagLoadFileDataBlock:
			if len(lf.DataBlock) != 0 {
				return nil, fmt.Errorf("%w: duplicate C4 load file data block", ErrInvalidLoadFile)
			}
			if len(value) == 0 {
				return nil, fmt.Errorf("%w: empty C4 load file data block", ErrInvalidLoadFile)
			}
			lf.DataBlock = append([]byte(nil), value...)

		case TagCipheredLoadFileDataBlock:
			return nil, fmt.Errorf("%w: D4 ciphered load file is not supported", ErrInvalidLoadFile)

		case TagICV:
			return nil, fmt.Errorf("%w: D3 ICV is not supported", ErrInvalidLoadFile)

		default:
			return nil, fmt.Errorf("%w: unexpected tag %02X", ErrInvalidLoadFile, tag)
		}

		rest = next
	}

	if len(lf.DataBlock) == 0 {
		return nil, fmt.Errorf("%w: missing C4 load file data block", ErrInvalidLoadFile)
	}
	return &lf, nil
}

// LoadFileDataBlockHashes computes the SHA-256 and SHA-1 digests
// over the Load File Data Block (the LFDB), NOT over the C4-wrapped
// Load File that gets streamed through LOAD. The hash is the input
// to INSTALL [for load]'s Load File Data Block Hash field per GP
// §11.5.2.3, and the spec is unambiguous that the digest is over
// the LFDB only — including the C4 tag and BER length in the hash
// would put the host out of agreement with every spec-conformant
// card.
//
// Both hashes are returned because GP §11.5 leaves the algorithm
// to card-side policy: SHA-1 is the historical default and the only
// algorithm guaranteed by older cards; SHA-256 is the modern
// recommendation. Callers select the algorithm via
// InstallOptions.LoadHash and pass through the bytes from this
// function unchanged.
func LoadFileDataBlockHashes(lfdb []byte) (sha256Sum, sha1Sum []byte, err error) {
	if len(lfdb) == 0 {
		return nil, nil, fmt.Errorf("%w: empty load file data block", ErrInvalidLoadFile)
	}
	s256 := sha256.Sum256(lfdb)
	s1 := sha1.Sum(lfdb) //nolint:gosec // legacy GP LFDBH compatibility
	return s256[:], s1[:], nil
}

// EncodeTLV emits a single BER TLV: tag byte followed by
// minimal-form BER length followed by value. Exposed for tests
// and for callers building DAP blocks externally; the typical
// host path goes through BuildPlainLoadFile.
func EncodeTLV(tag byte, value []byte) ([]byte, error) {
	length, err := EncodeBERLength(len(value))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(length)+len(value))
	out = append(out, tag)
	out = append(out, length...)
	out = append(out, value...)
	return out, nil
}

// EncodeBERLength returns the minimal-form BER length encoding for
// n. GP Load Files use short form (≤127), 0x81 form (128..255), or
// 0x82 form (256..65535). 0x83 form is also produced for values up
// to 16777215 to support payloads in that range; larger values are
// rejected because the GP spec does not pin a maximum but in
// practice no real load file exceeds 16MB.
func EncodeBERLength(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("%w: negative BER length", ErrInvalidLoadFile)
	}
	switch {
	case n <= 0x7F:
		return []byte{byte(n)}, nil
	case n <= 0xFF:
		return []byte{0x81, byte(n)}, nil
	case n <= 0xFFFF:
		return []byte{0x82, byte(n >> 8), byte(n)}, nil
	case n <= 0xFFFFFF:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}, nil
	default:
		return nil, fmt.Errorf("%w: BER length %d too large", ErrInvalidLoadFile, n)
	}
}

// DecodeBERLength parses a minimal-form BER length from b and
// returns (length, bytes consumed, error). Rejects:
//
//   - Indefinite form (0x80): not allowed in GP TLVs.
//   - Lengths longer than 0x83 (more than 3 octets): outside the
//     range any real GP Load File needs and outside what this
//     package supports.
//   - Non-minimal encodings: e.g. encoding 0x42 as 0x81 0x42, or
//     0x100 as 0x82 0x00 0xFF... 0x00. Catches malformed host
//     output early; spec-conformant decoders only accept minimal
//     form.
func DecodeBERLength(b []byte) (n int, used int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: missing BER length", ErrInvalidLoadFile)
	}

	first := b[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}

	octets := int(first & 0x7F)
	if octets == 0 {
		return 0, 0, fmt.Errorf("%w: indefinite BER length not allowed", ErrInvalidLoadFile)
	}
	if octets > 3 {
		return 0, 0, fmt.Errorf("%w: BER length uses %d octets, max 3", ErrInvalidLoadFile, octets)
	}
	if len(b) < 1+octets {
		return 0, 0, fmt.Errorf("%w: truncated BER length", ErrInvalidLoadFile)
	}

	var out int
	for i := 0; i < octets; i++ {
		out = (out << 8) | int(b[1+i])
	}

	// Reject non-minimal encodings.
	if out <= 0x7F {
		return 0, 0, fmt.Errorf("%w: non-minimal BER length (value fits short form)", ErrInvalidLoadFile)
	}
	if out <= 0xFF && octets > 1 {
		return 0, 0, fmt.Errorf("%w: non-minimal BER length (value fits 1-octet long form)", ErrInvalidLoadFile)
	}
	if out <= 0xFFFF && octets > 2 {
		return 0, 0, fmt.Errorf("%w: non-minimal BER length (value fits 2-octet long form)", ErrInvalidLoadFile)
	}

	return out, 1 + octets, nil
}

// readTLVValue parses one TLV from b, returning the value bytes,
// the remainder of b after the TLV, and any error. Used internally
// by ParseLoadFile and parseDAPBlock; not exported because callers
// should go through ParseLoadFile.
func readTLVValue(b []byte) (value, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("%w: truncated TLV", ErrInvalidLoadFile)
	}
	n, used, err := DecodeBERLength(b[1:])
	if err != nil {
		return nil, nil, err
	}
	start := 1 + used
	if n < 0 || start+n > len(b) {
		return nil, nil, fmt.Errorf("%w: TLV length exceeds remaining bytes", ErrInvalidLoadFile)
	}
	return b[start : start+n], b[start+n:], nil
}

func encodeDAPBlock(d DAPBlock) ([]byte, error) {
	if err := validateAIDBytes(d.SDAID); err != nil {
		return nil, fmt.Errorf("SD AID: %w", err)
	}
	if len(d.Signature) == 0 {
		return nil, fmt.Errorf("%w: DAP signature is empty", ErrInvalidLoadFile)
	}

	sd, err := EncodeTLV(TagSecurityDomainAID, d.SDAID)
	if err != nil {
		return nil, err
	}
	sig, err := EncodeTLV(TagLoadFileDataBlockSignature, d.Signature)
	if err != nil {
		return nil, err
	}
	body := append(sd, sig...)
	return EncodeTLV(TagDAPBlock, body)
}

func parseDAPBlock(value []byte) (DAPBlock, error) {
	var out DAPBlock
	rest := value

	for len(rest) > 0 {
		tag := rest[0]
		v, next, err := readTLVValue(rest)
		if err != nil {
			return DAPBlock{}, err
		}

		switch tag {
		case TagSecurityDomainAID:
			if len(out.SDAID) != 0 {
				return DAPBlock{}, fmt.Errorf("%w: duplicate DAP SD AID", ErrInvalidLoadFile)
			}
			if err := validateAIDBytes(v); err != nil {
				return DAPBlock{}, err
			}
			out.SDAID = append([]byte(nil), v...)

		case TagLoadFileDataBlockSignature:
			if len(out.Signature) != 0 {
				return DAPBlock{}, fmt.Errorf("%w: duplicate DAP signature", ErrInvalidLoadFile)
			}
			if len(v) == 0 {
				return DAPBlock{}, fmt.Errorf("%w: empty DAP signature", ErrInvalidLoadFile)
			}
			out.Signature = append([]byte(nil), v...)

		default:
			return DAPBlock{}, fmt.Errorf("%w: unexpected DAP tag %02X", ErrInvalidLoadFile, tag)
		}

		rest = next
	}

	if len(out.SDAID) == 0 {
		return DAPBlock{}, fmt.Errorf("%w: DAP block missing SD AID", ErrInvalidLoadFile)
	}
	if len(out.Signature) == 0 {
		return DAPBlock{}, fmt.Errorf("%w: DAP block missing signature", ErrInvalidLoadFile)
	}
	return out, nil
}

// validateAIDBytes enforces the ISO/IEC 7816-5 AID length bounds:
// 5 to 16 bytes inclusive.
func validateAIDBytes(a []byte) error {
	if len(a) < 5 || len(a) > 16 {
		return fmt.Errorf("%w: AID length %d invalid, must be 5..16 bytes", ErrInvalidLoadFile, len(a))
	}
	return nil
}
