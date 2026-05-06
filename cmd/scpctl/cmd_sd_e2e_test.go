package main

// End-to-end tests for the sd keys / sd allowlist write verbs
// against the scp03 package's MockCard.
//
// These tests sit one layer above the per-phase unit tests. Where
// the unit tests stop at "open SCP03 fails against the regular
// mockcard.Card" (proving validation runs cleanly), these tests
// wire up scp03.NewMockCard(scp03.DefaultKeys) — a transport that
// actually speaks SCP03 against the well-known factory key set —
// so the command's --confirm-write path runs to completion. We
// then use mockCard.Recorded() to assert the right APDU shape
// emerged on the wire.
//
// What this lets us prove that the unit tests can't:
//
//   - INS / P1 / P2 of the destructive APDU is correct
//   - The body of PUT KEY / STORE DATA / DELETE KEY / GENERATE EC
//     KEY contains the operator's input as expected
//   - GENERATE EC KEY response parsing produces a valid P-256 SPKI
//     that the CLI can write to --out as PEM
//
// What we still don't prove here:
//
//   - Round-trip read-after-write consistency. The scp03 mock does
//     not persist SD inventory; a follow-up GET STATUS would NOT
//     return what was just PUT. That measurement lives in the
//     hardware lab test (lab_scp11c_test.go) and the byte-exact
//     transcript tests in scp03/ and scp11/.
//
// SCP03 default keys: scp03.DefaultKeys. Our CLI's default
// --scp03-* flag values resolve to the same keys (registerSCP03Key
// Flags' factory default), so we don't need to pass --scp03-keys
// explicitly. If that default ever changes, every test here that
// relies on the implicit match will still pass — but the wire log
// will show ENC/MAC derivation against whatever the new default is.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/scp/scp03"
	"github.com/PeculiarVentures/scp/transport"
)

// envForSCP03Mock wires an scp03.MockCard into a runEnv such that
// any command's transport-open call reaches the mock. The mock
// already negotiates SCP03 against scp03.DefaultKeys, so commands
// that use registerSCP03KeyFlags' factory default reach a working
// authenticated session and proceed to the destructive APDU.
//
// Returns the env, an output buffer for assertions, and the mock
// itself so the test can call mockCard.Recorded() at the end.
func envForSCP03Mock(t *testing.T) (*runEnv, *bytes.Buffer, *scp03.MockCard) {
	t.Helper()
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	var buf bytes.Buffer
	env := &runEnv{
		out: &buf, errOut: &buf,
		connect: func(_ context.Context, _ string) (transport.Transport, error) {
			return mockCard.Transport(), nil
		},
	}
	return env, &buf, mockCard
}

// recordedAPDUWithINS returns the first recorded APDU whose INS
// matches, or nil if none is present. Tests assert presence of a
// specific INS this way rather than indexing into Recorded() by
// position — the SCP03 handshake logs nothing destructive, but
// future mock changes that add introspection APDUs shouldn't
// silently break our assertions.
func recordedAPDUWithINS(rec []scp03.RecordedAPDU, ins byte) *scp03.RecordedAPDU {
	for i := range rec {
		if rec[i].INS == ins {
			return &rec[i]
		}
	}
	return nil
}

// recordedAPDUsWithINS returns ALL recorded APDUs matching INS.
// Used when a single command emits multiple APDUs of the same INS
// (e.g. STORE DATA cert chain emits one STORE DATA per chunk).
func recordedAPDUsWithINS(rec []scp03.RecordedAPDU, ins byte) []scp03.RecordedAPDU {
	var out []scp03.RecordedAPDU
	for _, r := range rec {
		if r.INS == ins {
			out = append(out, r)
		}
	}
	return out
}

// --- Phase 2: sd allowlist set / clear ---

// TestE2E_SDAllowlistSet emits STORE DATA (INS=0xE2) carrying the
// allowlist payload tagged 0x70 with the provided certificate
// serials. The allowlist binds to a specific key reference (KID/KVN);
// the bound serial set determines which OCE leaf-cert serials the
// card will accept during SCP11a/c authentication against that key.
func TestE2E_SDAllowlistSet(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDAllowlistSet(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--serial", "0x1234567890ABCDEF",
		"--serial", "0xFEDCBA9876543210",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdSDAllowlistSet: %v\n%s", err, buf.String())
	}

	storeData := recordedAPDUWithINS(mockCard.Recorded(), 0xE2)
	if storeData == nil {
		t.Fatalf("expected STORE DATA (INS=0xE2) in recorded APDUs; got %+v", mockCard.Recorded())
	}
	// The allowlist payload is tagged 0x70 per
	// securitydomain.tagAllowList. The serials appear inside as
	// child TLVs.
	if !bytes.Contains(storeData.Data, []byte{0x70}) {
		t.Errorf("STORE DATA body missing tag 0x70 (allowlist); body=%X", storeData.Data)
	}
	// Both serial values must be present somewhere in the body —
	// they're the operator's specified content. Big-endian byte
	// order, leading zeros stripped per ASN.1 INTEGER convention.
	for _, hex := range [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF},
		{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
	} {
		if !bytes.Contains(storeData.Data, hex) {
			t.Errorf("STORE DATA body missing serial bytes %X; body=%X", hex, storeData.Data)
		}
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Errorf("expected PASS in report output; got:\n%s", buf.String())
	}
}

// TestE2E_SDAllowlistClear emits STORE DATA (INS=0xE2) with an
// empty allowlist. The clear is implemented as
// StoreAllowlist(ref, nil) so the on-the-wire shape is the same
// STORE DATA shape as set, just with no serial children inside the
// 0x70 tag.
func TestE2E_SDAllowlistClear(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDAllowlistClear(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdSDAllowlistClear: %v\n%s", err, buf.String())
	}

	storeData := recordedAPDUWithINS(mockCard.Recorded(), 0xE2)
	if storeData == nil {
		t.Fatalf("expected STORE DATA (INS=0xE2) in recorded APDUs; got %+v", mockCard.Recorded())
	}
	if !bytes.Contains(storeData.Data, []byte{0x70}) {
		t.Errorf("STORE DATA body missing tag 0x70 (allowlist); body=%X", storeData.Data)
	}
}

// --- Phase 3: sd keys delete ---

// TestE2E_SDKeysDelete_OneKey emits DELETE KEY (INS=0xE4) with
// P2=KVN and a body that includes the KID tag (0xD0).
func TestE2E_SDKeysDelete_OneKey(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
		"--confirm-delete-key",
	})
	if err != nil {
		t.Fatalf("cmdSDKeysDelete: %v\n%s", err, buf.String())
	}

	delAPDU := recordedAPDUWithINS(mockCard.Recorded(), 0xE4)
	if delAPDU == nil {
		t.Fatalf("expected DELETE KEY (INS=0xE4) in recorded APDUs; got %+v", mockCard.Recorded())
	}
	// Body carries Tlv(0xD0, kid) per GP §11.6.2.
	if !bytes.Contains(delAPDU.Data, []byte{0xD0, 0x01, 0x11}) {
		t.Errorf("DELETE KEY body missing Tlv(0xD0, 0x11); body=%X", delAPDU.Data)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Errorf("expected PASS in report; got:\n%s", buf.String())
	}
}

// TestE2E_SDKeysDelete_AllAtKVN with --all does not require --kid;
// we expect a DELETE KEY APDU with no KID-tag body, addressing the
// KVN only.
func TestE2E_SDKeysDelete_AllAtKVN(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kvn", "03", "--all",
		"--confirm-delete-key",
	})
	if err != nil {
		t.Fatalf("cmdSDKeysDelete --all: %v\n%s", err, buf.String())
	}
	if recordedAPDUWithINS(mockCard.Recorded(), 0xE4) == nil {
		t.Fatalf("expected DELETE KEY (INS=0xE4) in recorded APDUs; got %+v", mockCard.Recorded())
	}
}

// --- Phase 4: sd keys generate ---

// TestE2E_SDKeysGenerate emits GENERATE EC KEY (Yubico INS=0xF1)
// and writes the returned SPKI to --out as a PEM PUBLIC KEY block.
// The mock synthesizes a fresh P-256 key in its response so the CLI
// has a real SPKI to write.
func TestE2E_SDKeysGenerate(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "spki.pem")

	err := cmdSDKeysGenerate(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--out", outPath,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("cmdSDKeysGenerate: %v\n%s", err, buf.String())
	}

	if recordedAPDUWithINS(mockCard.Recorded(), 0xF1) == nil {
		t.Fatalf("expected GENERATE EC KEY (INS=0xF1) in recorded APDUs; got %+v", mockCard.Recorded())
	}
	// SPKI file must exist and parse as a P-256 PUBLIC KEY.
	spkiBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read --out: %v", err)
	}
	block, _ := pem.Decode(spkiBytes)
	if block == nil {
		t.Fatalf("--out file is not PEM:\n%s", spkiBytes)
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX pub: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("not an ECDSA public key: %T", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Errorf("curve = %s, want P-256", ecPub.Curve.Params().Name)
	}
}

// --- Phase 5a: sd keys import (SCP03 path) ---

// TestE2E_SDKeysImportSCP03 emits PUT KEY (INS=0xD8) with the new
// SCP03 AES-128 key triple in the body. Asserts the APDU shape and
// that the report records the install as PASS.
func TestE2E_SDKeysImportSCP03(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	hex16 := strings.Repeat("AB", 16)
	err := cmdSDKeysImport(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FE",
		"--new-scp03-enc", hex16,
		"--new-scp03-mac", hex16,
		"--new-scp03-dek", hex16,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("import (SCP03): %v\n%s", err, buf.String())
	}

	putKey := recordedAPDUWithINS(mockCard.Recorded(), 0xD8)
	if putKey == nil {
		t.Fatalf("expected PUT KEY (INS=0xD8) in recorded APDUs; got %+v", mockCard.Recorded())
	}
	// PUT KEY P1 carries the replace-KVN. We sent --replace-kvn 00
	// (default), which means "additive install" → P1=0x00.
	if putKey.P1 != 0x00 {
		t.Errorf("PUT KEY P1 = 0x%02X, want 0x00 (additive install)", putKey.P1)
	}
	// PUT KEY P2 carries the new key set's first KID with bit 8
	// (0x80) set to indicate "multiple keys in this command" per
	// putKeySCP03Cmd / GP §11.8.2.2. SCP03 KID is 0x01, so the
	// expected wire byte is 0x01 | 0x80 = 0x81.
	if putKey.P2 != 0x81 {
		t.Errorf("PUT KEY P2 = 0x%02X, want 0x81 (KID 0x01 | multi-key flag 0x80)", putKey.P2)
	}
	// Body starts with KVN (0xFE) per the PUT KEY format.
	if len(putKey.Data) < 1 || putKey.Data[0] != 0xFE {
		t.Errorf("PUT KEY body should start with KVN=0xFE; body=%X", putKey.Data)
	}
	// Body shape: KVN || (Tlv(0x88, 16 bytes) || 0x03 || KCV[3]) × 3
	// = 1 + 3 × (1 + 1 + 16 + 1 + 3) = 67 bytes for AES-128.
	if len(putKey.Data) != 67 {
		t.Errorf("PUT KEY body length = %d, want 67 (KVN + 3×(tag+len+16+kcvlen+3kcv))", len(putKey.Data))
	}
	// Body should contain THREE occurrences of "88 10" (tag 0x88
	// followed by length 0x10 = 16 bytes for AES-128 keys).
	if c := bytes.Count(putKey.Data, []byte{0x88, 0x10}); c != 3 {
		t.Errorf("PUT KEY body should contain 3 SCP03 key-set TLV headers (88 10); got %d", c)
	}
	// SECURITY: the raw new-key bytes (0xAB × 16) MUST NOT appear in
	// the body. PUT KEY encrypts each key under the static DEK before
	// transmission. If the encrypted body contains 16 consecutive
	// 0xAB bytes, the encryption was bypassed — that would be a
	// catastrophic library bug. (The mock decrypts via static DEK and
	// recomputes KCV; the encryption side's correctness is what this
	// negative assertion guards.)
	if bytes.Contains(putKey.Data, bytes.Repeat([]byte{0xAB}, 16)) {
		t.Errorf("PUT KEY body contains raw new-key bytes; PUT KEY must encrypt under static DEK before transmission. body=%X", putKey.Data)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Errorf("expected PASS in report; got:\n%s", buf.String())
	}
}

// --- Phase 5b: sd keys import (SCP11 SD path) ---

// TestE2E_SDKeysImportSCP11SD emits PUT KEY for the EC private key
// and STORE DATA for the cert chain. Verifies both APDUs are
// emitted and ordering is PUT KEY first (the chain is associated
// with an installed key).
func TestE2E_SDKeysImportSCP11SD(t *testing.T) {
	dir := t.TempDir()
	priv := genE2EP256Key(t)
	keyPath := writeE2EKeyPEM(t, dir, priv)
	certPath := writeE2ESelfSignedCert(t, dir, priv, "leaf")

	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysImport(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "01",
		"--key-pem", keyPath, "--certs", certPath,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("import (SCP11 SD): %v\n%s", err, buf.String())
	}

	rec := mockCard.Recorded()
	putKey := recordedAPDUWithINS(rec, 0xD8)
	if putKey == nil {
		t.Fatalf("expected PUT KEY (INS=0xD8); got %+v", rec)
	}
	storeData := recordedAPDUsWithINS(rec, 0xE2)
	if len(storeData) == 0 {
		t.Fatalf("expected STORE DATA (INS=0xE2) for cert chain; got %+v", rec)
	}
	// PUT KEY before STORE DATA: scan the recorded order.
	var putKeyIdx, firstStoreDataIdx int = -1, -1
	for i, r := range rec {
		if r.INS == 0xD8 && putKeyIdx < 0 {
			putKeyIdx = i
		}
		if r.INS == 0xE2 && firstStoreDataIdx < 0 {
			firstStoreDataIdx = i
		}
	}
	if putKeyIdx < 0 || firstStoreDataIdx < 0 {
		t.Fatalf("PUT KEY or STORE DATA missing in recorded order: %+v", rec)
	}
	if putKeyIdx > firstStoreDataIdx {
		t.Errorf("STORE DATA emitted before PUT KEY; cert chain is supposed to attach to an installed key. PUT KEY idx=%d, STORE DATA idx=%d",
			putKeyIdx, firstStoreDataIdx)
	}

	// The cert chain's leaf (the cert we wrote) must NOT appear in
	// the report output as raw bytes. We already test private-key
	// non-leakage in unit tests; this E2E test pins that the cert
	// body, which IS public material, surfaces only in the JSON
	// metadata (cert_count) — not as base64/hex in the text report.
	if strings.Contains(buf.String(), "BEGIN CERTIFICATE") {
		t.Errorf("text report should not include cert PEM; got:\n%s", buf.String())
	}
}

// --- Phase 5c: sd keys import (CA/OCE trust anchor path) ---

// TestE2E_SDKeysImportTrustAnchor emits PUT KEY for the public key
// and STORE DATA for the SKI registration (StoreCaIssuer).
func TestE2E_SDKeysImportTrustAnchor(t *testing.T) {
	dir := t.TempDir()
	priv := genE2EP256Key(t)
	// Use a cert with a known SubjectKeyId so we can verify the SKI
	// shows up in the STORE DATA body.
	skiBytes := []byte{0xCA, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12}
	certPath := writeE2ECertWithSKI(t, dir, priv, skiBytes, "anchor")

	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysImport(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "10", "--kvn", "01",
		"--key-pem", certPath,
		"--confirm-write",
	})
	if err != nil {
		t.Fatalf("import (trust anchor): %v\n%s", err, buf.String())
	}

	rec := mockCard.Recorded()
	putKey := recordedAPDUWithINS(rec, 0xD8)
	if putKey == nil {
		t.Fatalf("expected PUT KEY (INS=0xD8); got %+v", rec)
	}
	storeData := recordedAPDUsWithINS(rec, 0xE2)
	if len(storeData) == 0 {
		t.Fatalf("expected STORE DATA (INS=0xE2) for SKI; got %+v", rec)
	}
	// SKI bytes must appear in one of the STORE DATA bodies.
	var sawSKI bool
	for _, sd := range storeData {
		if bytes.Contains(sd.Data, skiBytes) {
			sawSKI = true
			break
		}
	}
	if !sawSKI {
		t.Errorf("SKI bytes %X not found in any STORE DATA body; recorded: %+v", skiBytes, storeData)
	}
}

// --- Read-side E2E tests (depend on the cert-store mock fix) ---

// TestE2E_SDKeys_ImportExport_Roundtrip drives the full chain
// life cycle: write a cert chain via sd keys import (SCP11 SD path,
// which stores chain at the same key reference as the private key),
// then read it back via sd keys export, and verify the bytes round-
// trip exactly.
//
// This is the highest-value E2E test in the file: it proves the
// complete operator workflow (install + read-back) works end-to-
// end against a faithful mock simulator. A regression in either the
// import-side STORE DATA emission OR the export-side parseCertificates
// would land an obvious failure here.
//
// Depends on:
//   - scp03 mock cert-store persistence (commit "scp03/mock:
//     cert-store persistence for STORE DATA / GET DATA tag BF21")
//   - mock SCP03 PUT KEY response synthesis (commit "scp03/mock:
//     synthesize SCP03 PUT KEY response per GP §11.8.2.3")
func TestE2E_SDKeys_ImportExport_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	priv := genE2EP256Key(t)
	keyPath := writeE2EKeyPEM(t, dir, priv)
	certPath := writeE2ESelfSignedCert(t, dir, priv, "roundtrip-leaf")

	// Snapshot the cert PEM we wrote so we can compare DER on read.
	originalCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert PEM: %v", err)
	}
	originalBlock, _ := pem.Decode(originalCertPEM)
	if originalBlock == nil {
		t.Fatalf("could not decode PEM written by writeE2ESelfSignedCert")
	}

	// Use a single mock instance for both import and export so the
	// cert-store map persists across the two commands.
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: import via sd keys import (SCP11 SD).
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--key-pem", keyPath, "--certs", certPath,
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("import phase: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: export via sd keys export. Read commands authenticate
	// via opt-in SCP03; --scp03-keys-default uses factory keys
	// (which match the mock's scp03.DefaultKeys), so the SCP03
	// session opens cleanly and GET DATA tag BF21 round-trips.
	exportPath := filepath.Join(dir, "exported.pem")
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--out", exportPath,
			"--scp03-keys-default",
		})
		if err != nil {
			t.Fatalf("export phase: %v\n%s", err, buf.String())
		}
	}

	// Verify: the exported PEM contains the cert bytes we imported.
	exportedPEM, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read exported PEM: %v", err)
	}
	exportedBlock, _ := pem.Decode(exportedPEM)
	if exportedBlock == nil {
		t.Fatalf("exported file is not PEM:\n%s", exportedPEM)
	}
	if exportedBlock.Type != "CERTIFICATE" {
		t.Errorf("exported PEM type = %q, want CERTIFICATE", exportedBlock.Type)
	}
	if !bytes.Equal(originalBlock.Bytes, exportedBlock.Bytes) {
		t.Errorf("import/export DER mismatch:\n  orig DER head:    %X\n  export DER head:  %X",
			originalBlock.Bytes[:min(32, len(originalBlock.Bytes))],
			exportedBlock.Bytes[:min(32, len(exportedBlock.Bytes))])
	}
	// Sanity: parse the exported DER as a cert and check its
	// public key matches the imported private key. The
	// integrity- and parsing-level guarantees combine here.
	exportedCert, err := x509.ParseCertificate(exportedBlock.Bytes)
	if err != nil {
		t.Fatalf("parse exported cert: %v", err)
	}
	exportedSPKI, err := x509.MarshalPKIXPublicKey(exportedCert.PublicKey)
	if err != nil {
		t.Fatalf("marshal exported SPKI: %v", err)
	}
	importedSPKI, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal imported SPKI: %v", err)
	}
	if !bytes.Equal(exportedSPKI, importedSPKI) {
		t.Errorf("exported cert public key does not match imported private key")
	}
}

// TestE2E_SDKeysExport_NoChain_Empty confirms the export verb's
// behavior when no chain is stored at the requested ref. The mock
// returns 6A88 (cert store) which the library translates to a nil
// chain; sd keys export's --allow-empty governs whether that's a
// success or a failure. Without --allow-empty: failure with a clear
// error. With --allow-empty: success, no file written.
func TestE2E_SDKeysExport_NoChain_Empty(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Without --allow-empty: should fail.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--out", filepath.Join(t.TempDir(), "out.pem"),
			"--scp03-keys-default",
		})
		if err == nil {
			t.Errorf("expected error for missing chain without --allow-empty; got success:\n%s", buf.String())
		}
	}

	// With --allow-empty: should succeed.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		dir := t.TempDir()
		outPath := filepath.Join(dir, "empty.pem")
		err := cmdSDKeysExport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "01",
			"--out", outPath,
			"--allow-empty",
			"--scp03-keys-default",
		})
		if err != nil {
			t.Errorf("--allow-empty should succeed for missing chain; got %v\n%s", err, buf.String())
		}
		// File may or may not exist depending on the export
		// semantics for empty chains; we don't pin that here, only
		// the success status.
	}
}

// TestE2E_SDKeysList_BasicInventory exercises the read path via
// sd keys list (no --certs). The mock returns syntheticKeyInfo
// for GET DATA tag E0 (KID=0x01, KVN=0xFF, AES-128 marker); the
// CLI parses and emits a report. This proves the GET STATUS-
// equivalent inventory query rounds trips through SCP03 to the mock
// and out as readable output.
func TestE2E_SDKeysList_BasicInventory(t *testing.T) {
	env, buf, _ := envForSCP03Mock(t)
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
	})
	if err != nil {
		t.Fatalf("cmdSDKeysList: %v\n%s", err, buf.String())
	}
	out := buf.String()
	// Mock's syntheticKeyInfo advertises KID=0x01, KVN=0xFF.
	for _, want := range []string{"0x01", "0xFF"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q\n%s", want, out)
		}
	}
}

// TestE2E_SDKeysDelete_OrphanAuth_Refused exercises the foot-gun
// guard: deleting the only SCP03 keyset on a card removes the
// only authentication path. Without --allow-orphan-auth the
// delete must be refused before the destructive APDU is sent;
// the recorded APDU log must show no DELETE KEY (INS=0xE4) for
// the key the operator named.
//
// Default mock inventory has one SCP03 keyset at 0x01/0xFF.
// Asking to delete that exact ref should fail with an
// orphan-auth error and emit no DELETE KEY APDU.
func TestE2E_SDKeysDelete_OrphanAuth_Refused(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FF",
		"--confirm-delete-key",
	})
	if err == nil {
		t.Fatalf("expected orphan-auth refusal, got success\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "orphan") {
		t.Errorf("expected orphan-auth diagnostic in error, got %q", err.Error())
	}
	// CRITICAL: no DELETE KEY APDU should have hit the card.
	if recordedAPDUWithINS(mockCard.Recorded(), 0xE4) != nil {
		t.Errorf("orphan-auth refusal must occur BEFORE DELETE KEY emission; got APDU: %+v",
			mockCard.Recorded())
	}
}

// TestE2E_SDKeysDelete_OrphanAuth_BypassFlag confirms
// --allow-orphan-auth lets the delete through. The operator has
// explicitly acknowledged the consequence; no soft-block should
// stand in the way.
func TestE2E_SDKeysDelete_OrphanAuth_BypassFlag(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FF",
		"--confirm-delete-key",
		"--allow-orphan-auth",
	})
	if err != nil {
		t.Fatalf("expected orphan-bypass success, got %v\n%s", err, buf.String())
	}
	if recordedAPDUWithINS(mockCard.Recorded(), 0xE4) == nil {
		t.Errorf("--allow-orphan-auth path should emit DELETE KEY; got %+v",
			mockCard.Recorded())
	}
}

// TestE2E_SDKeysDelete_NonSCP03_NoOrphanCheckTrigger confirms the
// orphan check doesn't fire when the targeted ref isn't SCP03 —
// deleting an SCP11 SD slot or a trust anchor doesn't affect the
// SCP03 keyset count, so the check passes regardless of inventory
// state.
//
// Mock has only the factory SCP03 key (0x01/0xFF). Operator asks
// to delete 0x11/0x03 (an SCP11 SD slot that isn't even installed
// on the mock — a no-op delete on a real card). Orphan check
// must compute "SCP03 count unchanged" and let the delete
// through without requiring --allow-orphan-auth.
func TestE2E_SDKeysDelete_NonSCP03_NoOrphanCheckTrigger(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "11", "--kvn", "03",
		"--confirm-delete-key",
	})
	if err != nil {
		t.Fatalf("delete of non-SCP03 ref should pass orphan check; got %v\n%s",
			err, buf.String())
	}
	if recordedAPDUWithINS(mockCard.Recorded(), 0xE4) == nil {
		t.Errorf("expected DELETE KEY APDU for non-SCP03 ref; got %+v",
			mockCard.Recorded())
	}
}

// TestE2E_SDKeysDelete_OrphanAuth_TwoKeysetsThenDeleteOne is the
// realistic key-rotation lifecycle: operator installs a new SCP03
// keyset alongside the factory one, then deletes the old factory.
// Inventory pre-delete has 2 SCP03 entries; post-delete has 1.
// Orphan check must allow this — there's still one SCP03 keyset
// remaining for the operator to authenticate against.
func TestE2E_SDKeysDelete_OrphanAuth_TwoKeysetsThenDeleteOne(t *testing.T) {
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: install a second SCP03 keyset at KVN=0xFE (new).
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "01", "--kvn", "FE",
			"--new-scp03-enc", "00112233445566778899AABBCCDDEEFF",
			"--new-scp03-mac", "11223344556677889900AABBCCDDEEFF",
			"--new-scp03-dek", "22334455667788990011AABBCCDDEEFF",
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("install second keyset: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: delete the factory keyset at KVN=0xFF. Pre-delete
	// inventory has 2 SCP03 keysets; post-delete has 1. Orphan
	// check should allow.
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kid", "01", "--kvn", "FF",
		"--confirm-delete-key",
	})
	if err != nil {
		t.Fatalf("delete should succeed when another SCP03 keyset remains; got %v\n%s",
			err, buf.String())
	}
}

// TestE2E_SDKeysDelete_OrphanAuth_AllAtKVN_FactoryRefused is the
// all-at-KVN variant of the orphan check: deleting every key at
// the factory KVN (0xFF) must trigger the same refusal because
// the factory SCP03 keyset lives at 0xFF and would be removed.
func TestE2E_SDKeysDelete_OrphanAuth_AllAtKVN_FactoryRefused(t *testing.T) {
	env, buf, mockCard := envForSCP03Mock(t)
	err := cmdSDKeysDelete(context.Background(), env, []string{
		"--reader", "fake",
		"--kvn", "FF", "--all",
		"--confirm-delete-key",
	})
	if err == nil {
		t.Fatalf("expected orphan-auth refusal for --all on factory KVN, got success\n%s",
			buf.String())
	}
	if !strings.Contains(err.Error(), "orphan") {
		t.Errorf("expected orphan-auth diagnostic, got %q", err.Error())
	}
	if recordedAPDUWithINS(mockCard.Recorded(), 0xE4) != nil {
		t.Errorf("--all orphan refusal must occur before APDU emission; got %+v",
			mockCard.Recorded())
	}
}

// keys import (SCP11 SD path) followed by sd keys list against the
// same mock instance, and asserts the imported key reference now
// appears in the inventory output.
//
// Before the inventory model was added to the SCP03 mock, this
// round-trip wasn't observable: GET DATA tag E0 returned a fixed
// blob advertising only the factory key (0x01/0xFF) regardless of
// what had been installed. With the inventory model in place, PUT
// KEY registers at the requested ref and the subsequent KIT
// response includes it.
//
// This is the third class of round-trip E2E coverage on the new
// sd-keys-cli surface, alongside import→export (cert-store path)
// and the per-verb APDU-emission tests:
//
//  1. APDU-emission tests: did the right wire bytes go out?
//  2. Cert-store round-trip: write a chain, read it back?
//  3. (this) Inventory round-trip: install a key, see it listed?
func TestE2E_SDKeys_ImportThenList_PostInstallStateVisible(t *testing.T) {
	dir := t.TempDir()
	priv := genE2EP256Key(t)
	keyPath := writeE2EKeyPEM(t, dir, priv)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: install an SCP11 SD private key at 0x11/0x03.
	// (No --certs — focus on inventory visibility, not the
	// cert-store path which is covered by the import→export
	// round-trip test.)
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "03",
			"--key-pem", keyPath,
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("import phase: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: list against the same mock. The imported ref
	// should now show up alongside the factory SCP03 key.
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
	})
	if err != nil {
		t.Fatalf("list phase: %v\n%s", err, buf.String())
	}
	out := buf.String()
	// Factory key still there.
	for _, want := range []string{"0x01", "0xFF"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing factory key marker %q\n%s", want, out)
		}
	}
	// Imported key now visible.
	for _, want := range []string{"0x11", "0x03"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing imported key marker %q\n%s", want, out)
		}
	}
}

// TestE2E_SDKeys_GenerateThenList_PostGenStateVisible drives sd
// keys generate (which emits GENERATE EC KEY INS=0xF1) and then
// asserts the generated ref appears in the inventory.
func TestE2E_SDKeys_GenerateThenList_PostGenStateVisible(t *testing.T) {
	dir := t.TempDir()
	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: generate an on-card EC key at 0x13/0x07.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysGenerate(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "13", "--kvn", "07",
			"--out", filepath.Join(dir, "gen.pem"),
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("generate phase: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: list. The generated ref should now appear.
	var buf bytes.Buffer
	env := &runEnv{out: &buf, errOut: &buf, connect: connect}
	err := cmdSDKeysList(context.Background(), env, []string{
		"--reader", "fake",
		"--scp03-keys-default",
	})
	if err != nil {
		t.Fatalf("list phase: %v\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"0x13", "0x07"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing generated key marker %q\n%s", want, out)
		}
	}
}

// TestE2E_SDKeys_InstallThenDeleteThenList_FullLifecycle exercises
// the complete install → delete → list flow on a single mock
// instance. Proves the inventory model handles all three phases:
//
//  1. PUT KEY registers the new ref
//  2. DELETE KEY unregisters it
//  3. GET DATA tag E0 reflects both transitions
//
// This is the most demanding round-trip test of the inventory
// model: it exercises every mutation path through real CLI verbs,
// not direct calls to the mock's helpers.
func TestE2E_SDKeys_InstallThenDeleteThenList_FullLifecycle(t *testing.T) {
	dir := t.TempDir()
	priv := genE2EP256Key(t)
	keyPath := writeE2EKeyPEM(t, dir, priv)

	mockCard := scp03.NewMockCard(scp03.DefaultKeys)
	connect := func(_ context.Context, _ string) (transport.Transport, error) {
		return mockCard.Transport(), nil
	}

	// Phase 1: install at 0x11/0x05.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysImport(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "05",
			"--key-pem", keyPath,
			"--confirm-write",
		})
		if err != nil {
			t.Fatalf("install phase: %v\n%s", err, buf.String())
		}
	}

	// Phase 2: list — confirm install is visible.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		if err := cmdSDKeysList(context.Background(), env, []string{
			"--reader", "fake", "--scp03-keys-default",
		}); err != nil {
			t.Fatalf("list (post-install): %v\n%s", err, buf.String())
		}
		out := buf.String()
		if !strings.Contains(out, "0x11") || !strings.Contains(out, "0x05") {
			t.Errorf("post-install list missing 0x11/0x05; out:\n%s", out)
		}
	}

	// Phase 3: delete 0x11/0x05.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		err := cmdSDKeysDelete(context.Background(), env, []string{
			"--reader", "fake",
			"--kid", "11", "--kvn", "05",
			"--confirm-delete-key",
		})
		if err != nil {
			t.Fatalf("delete phase: %v\n%s", err, buf.String())
		}
	}

	// Phase 4: list — confirm delete is reflected. Factory key
	// must still be there; deleted key must be gone.
	{
		var buf bytes.Buffer
		env := &runEnv{out: &buf, errOut: &buf, connect: connect}
		if err := cmdSDKeysList(context.Background(), env, []string{
			"--reader", "fake", "--scp03-keys-default",
		}); err != nil {
			t.Fatalf("list (post-delete): %v\n%s", err, buf.String())
		}
		out := buf.String()
		if !strings.Contains(out, "0x01") || !strings.Contains(out, "0xFF") {
			t.Errorf("factory key removed by unrelated delete; out:\n%s", out)
		}
		// Both "0x11" and "0x05" must be gone — search for the
		// pair as a single substring is unreliable (output may
		// have whitespace), so we check that neither appears.
		// (The factory key markers 0x01/0xFF can still appear,
		// but there's no other key with KID=0x11 or KVN=0x05 in
		// the inventory after delete.)
		if strings.Contains(out, "0x11") {
			t.Errorf("deleted KID 0x11 still in list output:\n%s", out)
		}
		if strings.Contains(out, "0x05") {
			t.Errorf("deleted KVN 0x05 still in list output:\n%s", out)
		}
	}
}

// min is provided by the standard library since Go 1.21 but the
// scp module declares go 1.22; this is here only because some Go
// linters dislike calls into builtin in the round-trip test above.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- fixture helpers (E2E-scoped, named to avoid colliding with
// helpers in cmd_sd_keys_import_scp11_test.go) ---

func genE2EP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func writeE2EKeyPEM(t *testing.T, dir string, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func writeE2ESelfSignedCert(t *testing.T, dir string, priv *ecdsa.PrivateKey, name string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, name+".crt.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func writeE2ECertWithSKI(t *testing.T, dir string, priv *ecdsa.PrivateKey, ski []byte, name string) string {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, name+".crt.pem")
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}
