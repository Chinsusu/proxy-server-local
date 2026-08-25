package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAESGCMEnvelopeRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	c, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := c.Seal([]byte("canary-password"), []byte("proxy-1"))
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Version != EnvelopeVersion || len(envelope.Nonce) == 0 {
		t.Fatalf("invalid envelope metadata version=%d nonce_length=%d ciphertext_length=%d", envelope.Version, len(envelope.Nonce), len(envelope.Ciphertext))
	}
	plain, err := c.Open(envelope, []byte("proxy-1"))
	defer wipe(plain)
	if err != nil || !bytes.Equal(plain, []byte("canary-password")) {
		t.Fatalf("round trip failed decrypted_length=%d err=%v", len(plain), err)
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := c.Open(envelope, []byte("proxy-1")); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestLoadKeyFileAcceptsExactOwnerOnlyModesAndRejectsOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if _, err := LoadKeyFile(path); !errors.Is(err, ErrACLUnsupported) {
			t.Fatalf("err=%v, want ACL unsupported", err)
		}
		return
	}

	for _, mode := range []os.FileMode{0o400, 0o600} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		key, err := LoadKeyFile(path)
		if err != nil || len(key) != KeySize {
			t.Fatalf("mode=%#o key length=%d err=%v", mode, len(key), err)
		}
	}
	for _, mode := range []os.FileMode{0o000, 0o440, 0o640, 0o644, 0o604, 0o700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyFile(path); !errors.Is(err, ErrUnsafeKeyFile) {
			t.Fatalf("mode=%#o err=%v, want unsafe key file", mode, err)
		}
	}
}

func TestLoadTokenFileAllowsOwnerReadOnlySystemdCredentialOnPOSIX(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt_secret")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'t'}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if _, err := LoadTokenFile(path); !errors.Is(err, ErrACLUnsupported) {
			t.Fatalf("err=%v, want ACL unsupported", err)
		}
		return
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	token, err := LoadTokenFile(path)
	if err != nil || len(token) != 32 {
		t.Fatalf("token length=%d err=%v", len(token), err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenFile(path); !errors.Is(err, ErrUnsafeTokenFile) {
		t.Fatalf("err=%v, want unsafe token file", err)
	}
}

func TestDecodeKeyWipesPartialHexOutputOnFailure(t *testing.T) {
	original := decodeKeyWipeHook
	defer func() { decodeKeyWipeHook = original }()
	var observed []byte
	decodeKeyWipeHook = func(value []byte) { observed = append([]byte(nil), value...) }
	malformed := append(bytes.Repeat([]byte("ab"), KeySize-1), []byte("ag")...)
	if _, err := decodeKey(malformed); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err=%v", err)
	}
	if len(observed) != KeySize {
		t.Fatalf("wiped output length=%d", len(observed))
	}
	for index, value := range observed {
		if value != 0 {
			t.Fatalf("partial decoded byte persisted at %d: %x", index, value)
		}
	}
}

func TestDecodeJSONStringBytesUnicodeAndFailureWipe(t *testing.T) {
	decoded, err := DecodeJSONStringBytes([]byte(`"a\n\uD83D\uDE00"`))
	if err != nil || string(decoded) != "a\n😀" {
		t.Fatalf("decoded=%q err=%v", decoded, err)
	}
	Wipe(decoded)
	for _, malformed := range [][]byte{[]byte(`"\uD83D"`), []byte(`"\uDE00"`), []byte(`"\u00zz"`), []byte(`"unterminated`), []byte(`null`), []byte(`"a""`), []byte("\"\xff\""), []byte(`"bad\x"`)} {
		if value, err := DecodeJSONStringBytes(malformed); err == nil || value != nil {
			t.Fatalf("malformed JSON secret accepted: %q value=%q err=%v", malformed, value, err)
		}
	}
}

func TestDecodeJSONStringBytesMatchesEncodingJSONForPermittedStrings(t *testing.T) {
	for _, plain := range []string{"", "ascii", `quote: "`, "emoji 😀", "line\nbreak", `slash/\`} {
		raw, err := json.Marshal(plain)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeJSONStringBytes(raw)
		if err != nil || !bytes.Equal(decoded, []byte(plain)) {
			t.Fatalf("plain=%q decoded=%q err=%v", plain, decoded, err)
		}
		Wipe(decoded)
	}
}

func TestStrictJSONObjectBudgetsDepthAndWideMembers(t *testing.T) {
	for _, depth := range []int{strictJSONMaxDepth - 2, strictJSONMaxDepth - 1} {
		body := []byte(`{"password":"ok"}`)
		for index := 0; index < depth; index++ {
			body = append([]byte(`{"x":`), append(body, '}')...)
		}
		if _, err := StrictJSONObject(body, []string{"x", "password"}); err != nil {
			t.Fatalf("depth=%d rejected: %v", depth, err)
		}
	}
	tooDeep := []byte(`{"password":"ok"}`)
	for index := 0; index < strictJSONMaxDepth; index++ {
		tooDeep = append([]byte(`{"x":`), append(tooDeep, '}')...)
	}
	if _, err := StrictJSONObject(tooDeep, []string{"x", "password"}); err == nil {
		t.Fatal("over-depth JSON accepted")
	}

	wide := make([]byte, 0, strictJSONMaxMembers*10)
	wide = append(wide, '{')
	for index := 0; index < strictJSONMaxMembers; index++ {
		if index > 0 {
			wide = append(wide, ',')
		}
		wide = append(wide, `"x`...)
		wide = append(wide, []byte(fmt.Sprintf("%d", index))...)
		wide = append(wide, `":0`...)
	}
	wide = append(wide, '}')
	if _, err := StrictJSONObject(wide, []string{}); err == nil { // root unknown must also reject; test token below separately.
		t.Fatal("wide unknown-object accepted")
	}
	// A permitted root uses exactly two members; nested wide values exercise
	// the global member budget without relaxing root unknown-field checks.
	nested := []byte(`{"password":"ok","meta":{`)
	for index := 0; index < strictJSONMaxMembers; index++ {
		if index > 0 {
			nested = append(nested, ',')
		}
		nested = append(nested, `"x`...)
		nested = append(nested, []byte(fmt.Sprintf("%d", index))...)
		nested = append(nested, `":0`...)
	}
	nested = append(nested, `}}`...)
	if _, err := StrictJSONObject(nested, []string{"password", "meta"}); err == nil {
		t.Fatal("over-member JSON accepted")
	}
	for _, count := range []int{strictJSONMaxTokens - 8, strictJSONMaxTokens + 1} {
		array := []byte(`{"password":"ok","meta":[`)
		for index := 0; index < count; index++ {
			if index > 0 {
				array = append(array, ',')
			}
			array = append(array, '0')
		}
		array = append(array, `]}`...)
		_, err := StrictJSONObject(array, []string{"password", "meta"})
		if count < strictJSONMaxTokens && err != nil {
			t.Fatalf("below-token-budget JSON rejected: %v", err)
		}
		if count > strictJSONMaxTokens && err == nil {
			t.Fatal("over-token-budget JSON accepted")
		}
	}
}

func FuzzStrictJSONObjectBudgeted(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"password":"ok"}`),
		[]byte(`{"password":"\uD83D\uDE00","meta":[0,true,null]}`),
		[]byte(`{"password":"ok","Password":"duplicate"}`),
		bytes.Repeat([]byte("["), strictJSONMaxDepth+2),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			return
		}
		_, _ = StrictJSONObject(body, []string{"password", "meta"})
	})
}

func FuzzDecodeJSONStringBytes(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`"ok"`), []byte(`"\uD83D\uDE00"`), []byte(`"bad\x"`), []byte(`"a""`), []byte("\"\xff\"")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		decoded, _ := DecodeJSONStringBytes(raw)
		Wipe(decoded)
	})
}
