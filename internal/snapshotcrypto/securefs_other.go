//go:build !linux

package snapshotcrypto

import "os"

type SourceState struct{}
type ReconciliationHandle struct{}

func HardenProcess() error { return ErrUnsupported }

func (SourceState) Metadata(string, string, string, uint64, string, uint32) Metadata {
	return Metadata{}
}

func OpenTrustedSource(string) (*os.File, SourceState, error) {
	return nil, SourceState{}, ErrUnsupported
}

func OpenTrustedQuiescedSource(string, uint32) (*os.File, SourceState, error) {
	return nil, SourceState{}, ErrUnsupported
}

func OpenTrustedCiphertext(string) (*os.File, error) { return nil, ErrUnsupported }

func RecheckSource(*os.File, SourceState) error { return ErrUnsupported }
func ValidatePublishedFile(SourceState, ExpectedMetadata, string) (PublicationReceipt, error) {
	return PublicationReceipt{}, ErrUnsupported
}
func ReceiptForOpenedFile(SourceState, string) PublicationReceipt { return PublicationReceipt{} }
func OpenPublishedForReconciliation(string) (*ReconciliationHandle, error) {
	return nil, ErrUnsupported
}
func (*ReconciliationHandle) File() *os.File              { return nil }
func (*ReconciliationHandle) Receipt() PublicationReceipt { return PublicationReceipt{} }
func (*ReconciliationHandle) ConfirmDurable(*ExpectedMetadata, *PublicationReceipt) (PublicationReceipt, error) {
	return PublicationReceipt{}, ErrUnsupported
}
func (*ReconciliationHandle) Abort() error { return nil }

type CiphertextPublisher struct{}

func CreateCiphertextPublisher(string) (*CiphertextPublisher, error) { return nil, ErrUnsupported }
func (*CiphertextPublisher) File() *os.File                          { return nil }
func (*CiphertextPublisher) Publish() (PublicationReceipt, error) {
	return PublicationReceipt{}, ErrUnsupported
}
func (*CiphertextPublisher) Abort() error { return nil }

type PlaintextPublisher struct{}

func CreatePlaintextPublisher(string) (*PlaintextPublisher, error) { return nil, ErrUnsupported }
func (*PlaintextPublisher) File() *os.File                         { return nil }
func (*PlaintextPublisher) Publish(uint32, uint32, uint32, uint64) (PublicationReceipt, error) {
	return PublicationReceipt{}, ErrUnsupported
}
func (*PlaintextPublisher) Abort() error { return nil }
