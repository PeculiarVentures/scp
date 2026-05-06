package main

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"strings"
	"testing"
)

func TestParseLoadHashFlag_DefaultIsNone(t *testing.T) {
	for _, v := range []string{"", "none", "NONE", "  none  "} {
		spec, err := parseLoadHashFlag(v)
		if err != nil {
			t.Errorf("parseLoadHashFlag(%q): %v", v, err)
			continue
		}
		if spec.Algorithm != "none" {
			t.Errorf("parseLoadHashFlag(%q).Algorithm = %q, want none", v, spec.Algorithm)
		}
		if got := spec.Resolve([]byte("ignored")); got != nil {
			t.Errorf("Resolve for none should return nil, got %x", got)
		}
	}
}

func TestParseLoadHashFlag_SHA1Computed(t *testing.T) {
	spec, err := parseLoadHashFlag("sha1")
	if err != nil {
		t.Fatal(err)
	}
	image := []byte("the load image bytes")
	got := spec.Resolve(image)
	want := sha1.Sum(image) //nolint:gosec
	if string(got) != string(want[:]) {
		t.Errorf("sha1 mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestParseLoadHashFlag_SHA256Computed(t *testing.T) {
	spec, err := parseLoadHashFlag("sha256")
	if err != nil {
		t.Fatal(err)
	}
	image := []byte("the load image bytes")
	got := spec.Resolve(image)
	want := sha256.Sum256(image)
	if string(got) != string(want[:]) {
		t.Errorf("sha256 mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestParseLoadHashFlag_HexLiteralAcceptsCaseAndSeparators(t *testing.T) {
	cases := []string{
		"hex:DEADBEEF",
		"hex:deadbeef",
		"hex:de:ad:be:ef",
		"hex:de ad be ef",
		"HEX:DEADBEEF",
	}
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	for _, c := range cases {
		spec, err := parseLoadHashFlag(c)
		if err != nil {
			t.Errorf("parseLoadHashFlag(%q): %v", c, err)
			continue
		}
		if spec.Algorithm != "hex" {
			t.Errorf("%q: Algorithm = %q, want hex", c, spec.Algorithm)
		}
		got := spec.Resolve([]byte("ignored"))
		if string(got) != string(want) {
			t.Errorf("%q: Resolve = %x, want %x", c, got, want)
		}
	}
}

func TestParseLoadHashFlag_HexLiteralRejectsMalformed(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hex:", "empty"},
		{"hex:zz", "invalid hex"},
		{"hex:abc", "invalid hex"}, // odd length
	}
	for _, c := range cases {
		_, err := parseLoadHashFlag(c.input)
		if err == nil {
			t.Errorf("parseLoadHashFlag(%q) should have failed", c.input)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("parseLoadHashFlag(%q): error %q should contain %q", c.input, err, c.want)
		}
	}
}

func TestParseLoadHashFlag_RejectsUnknownAlgorithm(t *testing.T) {
	_, err := parseLoadHashFlag("md5")
	if err == nil {
		t.Fatal("expected rejection of md5")
	}
	if !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("error should say 'unrecognized': %v", err)
	}
}

func TestLoadHashSpec_LabelIncludesByteLengthForHex(t *testing.T) {
	spec, err := parseLoadHashFlag("hex:DEADBEEF")
	if err != nil {
		t.Fatal(err)
	}
	label := spec.Label()
	if !strings.Contains(label, "hex") {
		t.Errorf("label should mention hex: %q", label)
	}
	if !strings.Contains(label, "4 bytes") {
		t.Errorf("label should report 4 bytes: %q", label)
	}
}
