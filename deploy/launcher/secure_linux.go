//go:build linux

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	trustPath        = "/etc/pgw/release-trust.manifest"
	releaseRootBase  = "/var/lib/pgw/releases"
	trustedLaunchTag = "pgw-release-launcher-v1"
	fixedPath        = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

func launch(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if name := forbiddenCallerEnvironment(os.Environ()); name != "" {
		return fmt.Errorf("forbidden caller environment: %s", name)
	}
	if err := validateArguments(args); err != nil {
		return err
	}

	trustFile, err := secureOpenAbsolute(trustPath, 0o600, 64*1024)
	if err != nil {
		return fmt.Errorf("open trust anchor: %w", err)
	}
	defer trustFile.Close()
	trust, err := parseTrust(bufio.NewReader(trustFile))
	if err != nil {
		return fmt.Errorf("parse trust anchor: %w", err)
	}

	releaseRoot := filepath.Join(releaseRootBase, trust.ReleaseID)
	rootFD, err := secureOpenDirectory(releaseRoot)
	if err != nil {
		return fmt.Errorf("open release root: %w", err)
	}
	defer unix.Close(rootFD)
	manifest, err := secureOpenRelative(rootFD, "release.manifest", 0o600, 256*1024)
	if err != nil {
		return fmt.Errorf("open release manifest: %w", err)
	}
	defer manifest.Close()
	manifestDigest, err := hashAndRewind(manifest)
	if err != nil || manifestDigest != trust.ManifestSHA256 {
		return errors.New("release manifest does not match pinned trust anchor")
	}
	entries, err := parseRelease(manifest)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	files := make([]*os.File, 0, len(entries))
	fdMap := make([]string, 0, len(entries))
	installerChildFD := -1
	for _, entry := range entries {
		file, openErr := secureOpenRelative(rootFD, entry.Path, entry.Mode, 128*1024*1024)
		if openErr != nil {
			closeFiles(files)
			return fmt.Errorf("open release entry %s: %w", entry.Path, openErr)
		}
		digest, hashErr := hashAndRewind(file)
		if hashErr != nil || digest != entry.SHA256 {
			file.Close()
			closeFiles(files)
			return fmt.Errorf("release entry digest mismatch: %s", entry.Path)
		}
		childFD := 3 + len(files)
		files = append(files, file)
		fdMap = append(fdMap, entry.Path+"="+strconv.Itoa(childFD))
		if entry.Path == "deploy/install-pgw.sh" {
			installerChildFD = childFD
		}
	}
	defer closeFiles(files)
	if installerChildFD < 0 {
		return errors.New("trusted installer entry is missing")
	}

	// No value from the caller survives. The three PGW variables below are
	// generated only after all root-owned descriptors and hashes are bound.
	os.Clearenv()
	return runVerifiedInstaller(installerChildFD, files, args, []string{
		"PATH=" + fixedPath,
		"LANG=C", "LC_ALL=C",
		"PGW_TRUSTED_LAUNCH=" + trustedLaunchTag,
		"PGW_RELEASE_ID=" + trust.ReleaseID,
		"PGW_RELEASE_FD_MAP=" + strings.Join(fdMap, ";"),
	})
}

func runVerifiedInstaller(installerChildFD int, files []*os.File, args, environment []string) error {
	cmd := exec.Command("/bin/bash", append([]string{"/proc/self/fd/" + strconv.Itoa(installerChildFD)}, args...)...)
	// The verified installer must not inherit an attacker-controlled working
	// directory. Python is subsequently invoked in isolated mode, but fixing the
	// child CWD also removes relative lookup ambiguity for every other tool.
	cmd.Dir = "/"
	cmd.Env = append([]string(nil), environment...)
	cmd.ExtraFiles = files
	// Installation is deliberately non-interactive. A nil stdin is connected
	// to the null device by os/exec; stdout/stderr remain operator evidence.
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func validateArguments(args []string) error {
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\r\n") || len(arg) > 4096 {
			return errors.New("invalid argument")
		}
	}
	return nil
}

func secureOpenAbsolute(name string, mode uint32, maxSize int64) (*os.File, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errors.New("path must be clean and absolute")
	}
	parent, base := filepath.Split(name)
	dirfd, err := secureOpenDirectory(filepath.Clean(parent))
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)
	return secureOpenRelative(dirfd, base, mode, maxSize)
}

func secureOpenDirectory(name string) (int, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return -1, errors.New("directory path must be clean and absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		if statErr := validateStat(next, true, 0, 0); statErr != nil {
			unix.Close(next)
			return -1, fmt.Errorf("unsafe directory component %s: %w", component, statErr)
		}
		fd = next
	}
	return fd, nil
}

func secureOpenRelative(rootFD int, name string, mode uint32, maxSize int64) (*os.File, error) {
	if !safeRelative(name) {
		return nil, errors.New("unsafe relative path")
	}
	components := strings.Split(name, "/")
	parent, err := unix.Dup(rootFD)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, openErr
		}
		if statErr := validateStat(next, true, 0, 0); statErr != nil {
			unix.Close(next)
			return nil, statErr
		}
		unix.Close(parent)
		parent = next
	}
	fd, err := unix.Openat(parent, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := validateStat(fd, false, mode, maxSize); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func validateStat(fd int, directory bool, mode uint32, maxSize int64) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		return errors.New("owner/mode violates root trust boundary")
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.New("not a directory")
		}
		return nil
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || uint32(st.Mode)&0o777 != mode || st.Size < 0 || st.Size > maxSize {
		return errors.New("file type, mode, or size mismatch")
	}
	return nil
}

func hashAndRewind(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		file.Close()
	}
}
