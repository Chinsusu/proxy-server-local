//go:build unix

package agent

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
)

var (
	forwarderGroupOnce sync.Once
	forwarderGroupID   int
	forwarderGroupErr  error
)

func secureForwarderReadable(path string, directory, skipOwnership bool) error {
	mode := os.FileMode(0o640)
	if directory {
		mode = 0o750
	}
	if skipOwnership {
		return secureSetOwnerMode(path, os.Geteuid(), os.Getegid(), mode, directory)
	}
	forwarderGroupOnce.Do(func() {
		group, err := user.LookupGroup("pgw-fwd")
		if err != nil {
			forwarderGroupErr = fmt.Errorf("agent: lookup pgw-fwd group: %w", err)
			return
		}
		forwarderGroupID, forwarderGroupErr = strconv.Atoi(group.Gid)
	})
	if forwarderGroupErr != nil {
		return forwarderGroupErr
	}
	// Keep the creator (pgw-agent) as owner so it can atomically replace files
	// and create children without CAP_CHOWN or CAP_DAC_OVERRIDE. Only the group
	// changes, and pgw-agent is provisioned as a member of pgw-fwd.
	if err := secureSetOwnerMode(path, -1, forwarderGroupID, mode, directory); err != nil {
		return fmt.Errorf("agent: set pgw-fwd permissions: %w", err)
	}
	return nil
}
