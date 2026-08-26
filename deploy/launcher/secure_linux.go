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
	releaseRootBase  = "/opt/pgw/releases"
	launcherPath     = "/usr/local/sbin/pgw-release-launcher"
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
	if len(args) > 0 && args[0] == "--adopt" {
		return adoptSelfManagedCandidate(args[1:])
	}
	if err := validateArguments(args); err != nil {
		return err
	}
	return launchInstalledRelease(args)
}

func launchInstalledRelease(args []string) error {
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

// adoptSelfManagedCandidate is the one-time, owner-operated path that stages a
// closed release assembly before invoking the fixed launcher. It deliberately
// accepts no network locator, checkout, Git reference, or caller-supplied hash:
// the maintainer transfers a root-owned candidate directory and records its
// candidate SHA-256 before this command is run.
func adoptSelfManagedCandidate(args []string) error {
	if err := validateArguments(args); err != nil {
		return err
	}
	assemblyPath, dryRun, installerArgs, err := parseAdoptArguments(args)
	if err != nil {
		return err
	}
	assemblyFD, err := secureOpenDirectory(assemblyPath)
	if err != nil {
		return fmt.Errorf("open candidate assembly: %w", err)
	}
	defer unix.Close(assemblyFD)

	trustFile, err := secureOpenRelative(assemblyFD, "release-trust.manifest", 0o600, 64*1024)
	if err != nil {
		return fmt.Errorf("open candidate trust manifest: %w", err)
	}
	trust, err := parseTrust(trustFile)
	trustFile.Close()
	if err != nil {
		return fmt.Errorf("parse candidate trust manifest: %w", err)
	}
	versionFile, err := secureOpenRelative(assemblyFD, "version.manifest", 0o600, 64*1024)
	if err != nil {
		return fmt.Errorf("open candidate version manifest: %w", err)
	}
	version, err := parseSelfManagedVersion(versionFile)
	versionFile.Close()
	if err != nil {
		return fmt.Errorf("parse candidate version manifest: %w", err)
	}
	if version.ReleaseID != trust.ReleaseID || version.ManifestSHA256 != trust.ManifestSHA256 {
		return errors.New("candidate version and trust manifest do not bind the same release")
	}
	entries, err := verifyCandidateRelease(assemblyFD, trust)
	if err != nil {
		return err
	}
	launcher, err := secureOpenRelative(assemblyFD, "pgw-release-launcher", 0o755, 128*1024*1024)
	if err != nil {
		return fmt.Errorf("open candidate launcher: %w", err)
	}
	launcherDigest, err := hashAndRewind(launcher)
	if err != nil || launcherDigest != version.LauncherSHA256 {
		launcher.Close()
		return errors.New("candidate launcher digest mismatch")
	}
	defer launcher.Close()

	if dryRun {
		fmt.Fprintf(os.Stdout, "self-managed candidate verified: release_id=%s manifest_sha256=%s\n", trust.ReleaseID, trust.ManifestSHA256)
		return nil
	}
	if err := stageCandidateRelease(assemblyFD, entries, trust); err != nil {
		return err
	}
	if err := atomicInstallFromFile("/usr/local/sbin", ".pgw-release-launcher.", launcherPath, launcher, 0o755, version.LauncherSHA256); err != nil {
		return fmt.Errorf("install self-managed launcher: %w", err)
	}
	trustBytes := []byte("format " + trustFormat + "\nrelease_id " + trust.ReleaseID + "\nmanifest_sha256 " + trust.ManifestSHA256 + "\n")
	if err := atomicInstallBytes("/etc/pgw", ".release-trust.", trustPath, trustBytes, 0o600); err != nil {
		return fmt.Errorf("install release trust manifest: %w", err)
	}

	// Re-enter through the fixed root-owned pathname. The installer verifies its
	// immediate parent, so calling it directly from the candidate is forbidden.
	cmd := exec.Command(launcherPath, installerArgs...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=" + fixedPath, "LANG=C", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func parseAdoptArguments(args []string) (string, bool, []string, error) {
	if len(args) == 0 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		return "", false, nil, errors.New("--adopt requires a clean absolute candidate directory")
	}
	assemblyPath := args[0]
	dryRun := false
	installerArgs := make([]string, 0, len(args)-1)
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			if dryRun {
				return "", false, nil, errors.New("duplicate --dry-run")
			}
			dryRun = true
		case "--migrate-legacy":
			installerArgs = append(installerArgs, args[i])
		case "--lan", "--wan":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", false, nil, fmt.Errorf("%s requires an interface", args[i])
			}
			installerArgs = append(installerArgs, args[i], args[i+1])
			i++
		default:
			return "", false, nil, fmt.Errorf("unsupported --adopt argument: %s", args[i])
		}
	}
	if dryRun && len(installerArgs) != 0 {
		return "", false, nil, errors.New("--dry-run cannot be combined with deployment arguments")
	}
	return assemblyPath, dryRun, installerArgs, nil
}

func verifyCandidateRelease(assemblyFD int, trust trustRecord) ([]releaseEntry, error) {
	manifest, err := secureOpenRelative(assemblyFD, "release/release.manifest", 0o600, 256*1024)
	if err != nil {
		return nil, fmt.Errorf("open candidate release manifest: %w", err)
	}
	manifestDigest, err := hashAndRewind(manifest)
	if err != nil || manifestDigest != trust.ManifestSHA256 {
		manifest.Close()
		return nil, errors.New("candidate release manifest does not match trust digest")
	}
	entries, err := parseRelease(manifest)
	manifest.Close()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		file, openErr := secureOpenRelative(assemblyFD, "release/"+entry.Path, entry.Mode, 128*1024*1024)
		if openErr != nil {
			return nil, fmt.Errorf("open candidate release entry %s: %w", entry.Path, openErr)
		}
		digest, hashErr := hashAndRewind(file)
		file.Close()
		if hashErr != nil || digest != entry.SHA256 {
			return nil, fmt.Errorf("candidate release entry digest mismatch: %s", entry.Path)
		}
	}
	return entries, nil
}

func stageCandidateRelease(assemblyFD int, entries []releaseEntry, trust trustRecord) error {
	if err := os.MkdirAll(releaseRootBase, 0o755); err != nil {
		return err
	}
	baseFD, err := secureOpenDirectory(releaseRootBase)
	if err != nil {
		return fmt.Errorf("open self-managed release root: %w", err)
	}
	defer unix.Close(baseFD)
	target := filepath.Join(releaseRootBase, trust.ReleaseID)
	if _, err := os.Lstat(target); err == nil {
		return errors.New("release id is already staged")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stage, err := os.MkdirTemp(releaseRootBase, ".incoming-")
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, 0o755); err != nil {
		return err
	}
	if err := copyCandidateEntry(assemblyFD, "release/release.manifest", filepath.Join(stage, "release.manifest"), 0o600, trust.ManifestSHA256); err != nil {
		return err
	}
	for _, entry := range entries {
		destination := filepath.Join(stage, entry.Path)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := copyCandidateEntry(assemblyFD, "release/"+entry.Path, destination, entry.Mode, entry.SHA256); err != nil {
			return err
		}
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, target); err != nil {
		return err
	}
	if err := syncDirectory(releaseRootBase); err != nil {
		return err
	}
	success = true
	return nil
}

func copyCandidateEntry(rootFD int, sourceName, destination string, mode uint32, expectedDigest string) error {
	source, err := secureOpenRelative(rootFD, sourceName, mode, 128*1024*1024)
	if err != nil {
		return err
	}
	defer source.Close()
	return copyOpenedFile(destination, source, mode, expectedDigest)
}

func atomicInstallFromFile(parent, prefix, destination string, source *os.File, mode uint32, expectedDigest string) error {
	if _, err := secureOpenDirectory(parent); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, prefix)
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := copyToOpenedFile(temporary, source, mode, expectedDigest); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func atomicInstallBytes(parent, prefix, destination string, value []byte, mode uint32) error {
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	if _, err := secureOpenDirectory(parent); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, prefix)
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(os.FileMode(mode)); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func copyOpenedFile(destination string, source *os.File, mode uint32, expectedDigest string) error {
	destinationFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(mode))
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	return copyToOpenedFile(destinationFile, source, mode, expectedDigest)
}

func copyToOpenedFile(destination, source *os.File, mode uint32, expectedDigest string) error {
	if err := destination.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(destination, hash), source); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("copied file digest mismatch")
	}
	return destination.Sync()
}

func syncDirectory(name string) error {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
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
