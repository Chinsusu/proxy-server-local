package snapshotcrypto

import (
	"errors"
	"fmt"
)

type CommitOutcome string

const (
	OutcomePreCommit               CommitOutcome = "pre_commit_failure"
	OutcomeCommitIndeterminate     CommitOutcome = "commit_indeterminate"
	OutcomeDurabilityIndeterminate CommitOutcome = "durability_indeterminate"
	OutcomeDurableAckFailure       CommitOutcome = "durable_committed_ack_failure"
)

const (
	ExitPreCommit               = 10
	ExitCommitIndeterminate     = 20
	ExitDurabilityIndeterminate = 21
	ExitDurableAckFailure       = 30
)

type PublicationReceipt struct {
	Destination string `json:"destination"`
	Known       bool   `json:"final_identity_known"`
	Device      uint64 `json:"final_device,omitempty"`
	Inode       uint64 `json:"final_inode,omitempty"`
	Size        uint64 `json:"final_size,omitempty"`
	UID         uint32 `json:"final_uid,omitempty"`
	GID         uint32 `json:"final_gid,omitempty"`
	Mode        uint32 `json:"final_mode,omitempty"`
}

type PublicationError struct {
	Outcome CommitOutcome
	Receipt PublicationReceipt
	Cause   error
}

func (failure *PublicationError) Error() string {
	if failure == nil {
		return "snapshot publication failure"
	}
	return fmt.Sprintf("snapshot publication %s: %v", failure.Outcome, failure.Cause)
}

func (failure *PublicationError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

func ExitCodeForOutcome(outcome CommitOutcome) int {
	switch outcome {
	case OutcomeCommitIndeterminate:
		return ExitCommitIndeterminate
	case OutcomeDurabilityIndeterminate:
		return ExitDurabilityIndeterminate
	case OutcomeDurableAckFailure:
		return ExitDurableAckFailure
	default:
		return ExitPreCommit
	}
}

func ClassifyPublicationError(err error) (CommitOutcome, PublicationReceipt) {
	var failure *PublicationError
	if errors.As(err, &failure) {
		return failure.Outcome, failure.Receipt
	}
	return OutcomePreCommit, PublicationReceipt{}
}

func publicationFailure(outcome CommitOutcome, receipt PublicationReceipt, cause error) error {
	return &PublicationError{Outcome: outcome, Receipt: receipt, Cause: cause}
}

func DurableAckFailure(receipt PublicationReceipt, cause error) error {
	return publicationFailure(OutcomeDurableAckFailure, receipt, cause)
}
