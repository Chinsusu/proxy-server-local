//go:build !linux

package snapshotcrypto

import (
	"errors"
	"testing"
)

func TestNonLinuxPublicationFailsClosed(t *testing.T) {
	if _, _, err := OpenTrustedSource("ignored"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("OpenTrustedSource error = %v", err)
	}
	if _, err := CreateCiphertextPublisher("ignored"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CreateCiphertextPublisher error = %v", err)
	}
	if _, err := CreatePlaintextPublisher("ignored"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CreatePlaintextPublisher error = %v", err)
	}
}
