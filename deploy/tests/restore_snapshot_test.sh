#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ "$(uname -s)" == Linux ]] || { printf 'snapshot ownership restore test: SKIP non-Linux\n'; exit 0; }
((EUID == 0)) || { printf 'snapshot ownership restore test: SKIP requires isolated root CI\n'; exit 0; }
# Exercise the complete capture/verify/restore path with a deliberately modest
# descriptor budget.  The over-budget oracle below lowers a child further.
ulimit -n 64

fixture="$(mktemp -d /var/lib/pgw-restore-test.XXXXXXXX)"
trap 'rm -rf -- "${fixture}"' EXIT
chmod 0700 "${fixture}"
live="${fixture}/live"
snapshot="${fixture}/snapshot"
metadata="${snapshot}/metadata.json"
install -d -m 0755 "${live}/var/lib" "${live}/etc" "${live}/srv"
install -d -m 0750 "${live}/var/lib/pgw/rules" "${live}/etc/pgw"
chmod 0750 "${live}/var/lib/pgw"
install -d -m 0710 "${live}/srv/pgw-cache"
install -d -m 0750 "${live}/var/lib/pgw/setgid-cache" "${live}/var/lib/pgw/sticky-cache"
printf 'api-state\n' >"${live}/var/lib/pgw/pgw.db"
printf 'agent-state\n' >"${live}/var/lib/pgw/rules/lkg.nft"
printf 'token-state\n' >"${live}/etc/pgw/agent.token"
printf 'cache-state\n' >"${live}/srv/pgw-cache/state"
printf 'setgid-state\n' >"${live}/var/lib/pgw/setgid-cache/state"
printf 'sticky-state\n' >"${live}/var/lib/pgw/sticky-cache/state"
chmod 0640 "${live}/var/lib/pgw/pgw.db"
chmod 0600 "${live}/var/lib/pgw/rules/lkg.nft" "${live}/etc/pgw/agent.token"
chmod 0644 "${live}/srv/pgw-cache/state"
chmod 0640 "${live}/var/lib/pgw/setgid-cache/state" "${live}/var/lib/pgw/sticky-cache/state"
chown 2001:2001 "${live}/var/lib/pgw"
chown 2002:2002 "${live}/var/lib/pgw/pgw.db"
chown 2003:2003 "${live}/var/lib/pgw/rules"
chown 2004:2004 "${live}/var/lib/pgw/rules/lkg.nft"
chown 2005:2005 "${live}/etc/pgw/agent.token"
chown 2006:2006 "${live}/srv/pgw-cache"
chown 2007:2007 "${live}/srv/pgw-cache/state"
chown 2008:2008 "${live}/var/lib/pgw/setgid-cache"
chown 2009:2009 "${live}/var/lib/pgw/setgid-cache/state"
chown 2010:2010 "${live}/var/lib/pgw/sticky-cache"
chown 2011:2011 "${live}/var/lib/pgw/sticky-cache/state"
# Ownership is deliberately applied before special mode bits: chown is allowed
# to clear setgid, which is the production restore ordering under test.
chmod 2750 "${live}/var/lib/pgw/setgid-cache"
chmod 1750 "${live}/var/lib/pgw/sticky-cache"
[[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/setgid-cache")" == 2008:2008:2750 ]]
[[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/sticky-cache")" == 2010:2010:1750 ]]

install -d -m 0700 "${snapshot}/files"
printf 'present\t/var/lib/pgw\npresent\t/etc/pgw/agent.token\npresent\t/srv/pgw-cache\nabsent\t/etc/pgw/obsolete.secret\n' >"${snapshot}/manifest"
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" capture-all "${snapshot}" "${live}" 0
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" metadata "${snapshot}"
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" verify "${snapshot}" payload /unused

# Production capture must reject short/growing/torn regular files and special
# objects without leaving a partial destination.  The deterministic torn-write
# oracle invokes capture_all_posix (the capture-all CLI implementation) and
# changes the same opened inode from the test process after its first real read;
# production exposes no failpoint.
/usr/bin/python3 -I - "${ROOT}/deploy/restore_snapshot.py" "${fixture}" <<'PY'
import hashlib,importlib.util,os,pathlib,sys
spec=importlib.util.spec_from_file_location("pgw_restore_capture",sys.argv[1])
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[2],"capture-mutation"); source_root=root/"source"; target_root=root/"target"
source_root.mkdir(parents=True); target_root.mkdir()
source_parent=os.open(source_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
target_parent=os.open(target_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
real_read=module.os.read
def run_case(name,reader,reason):
    source=source_root/name; target=target_root/name
    source.write_bytes(b"abcd")
    module.os.read=reader(source)
    try:
        try: module.capture_node(source_parent,name,target_parent,name,"root/"+name,module.ResourceBudget())
        except SystemExit as error: assert str(error)==reason,(name,str(error))
        else: raise AssertionError(name+" capture unexpectedly passed")
        assert not target.exists(),name+" left partial output"
    finally:
        module.os.read=real_read
        source.unlink()
run_case("shrink",lambda source: (lambda fd,size:b""),"snapshot source shrank while copying file")
def growing_reader(source):
    def read(fd,size):
        if size==1: return b"x"
        return real_read(fd,size)
    return read
run_case("grow",growing_reader,"snapshot source grew while copying file")
capture_root=root/"capture-all-torn"; system_root=capture_root/"system"
snapshot_root=capture_root/"snapshot"; live_file=system_root/"var/lib/pgw/pgw.db"
live_file.parent.mkdir(parents=True); (snapshot_root/"files").mkdir(parents=True)
live_file.write_bytes(b"A"*(3*1024*1024))
(snapshot_root/"manifest").write_text("present\t/var/lib/pgw/pgw.db\n",encoding="utf-8")
before_hash=hashlib.sha256(live_file.read_bytes()).hexdigest(); mutation_marker=capture_root/"mutation-reached"
mutated=False
def capture_all_reader(fd,size):
    global mutated
    chunk=real_read(fd,size)
    if chunk and not mutated and os.fstat(fd).st_ino==live_file.stat().st_ino:
        mutated=True
        with open(live_file,"r+b",buffering=0) as handle:
            handle.seek(0); handle.write(b"Z"); os.fsync(handle.fileno())
        mutation_marker.write_text("same-inode-same-size-write\n",encoding="ascii")
        marker_fd=os.open(mutation_marker,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(marker_fd)
        finally: os.close(marker_fd)
    return chunk
module.os.read=capture_all_reader
try:
    try: module.capture_all_posix(str(snapshot_root),str(system_root),0)
    except SystemExit as error: assert str(error)=="snapshot source changed while copying file",str(error)
    else: raise AssertionError("capture-all torn write unexpectedly passed")
finally: module.os.read=real_read
assert mutated and mutation_marker.read_text(encoding="ascii")=="same-inode-same-size-write\n"
assert hashlib.sha256(live_file.read_bytes()).hexdigest()!=before_hash
assert live_file.stat().st_size==3*1024*1024
assert not any((snapshot_root/"files").iterdir()),"capture-all left partial payload"
fifo=source_root/"fifo"; os.mkfifo(fifo)
try:
    module.capture_node(source_parent,"fifo",target_parent,"fifo","root/fifo",module.ResourceBudget())
except SystemExit as error: assert str(error)=="unsupported live snapshot object type",str(error)
else: raise AssertionError("FIFO capture unexpectedly passed")
assert not (target_root/"fifo").exists()
os.close(target_parent); os.close(source_parent)
print("snapshot capture mutation tests: PASS")
PY

set +e
fd_limit_error="$(
    (
        ulimit -n 40
        /usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" verify \
            "${snapshot}" payload /unused
    ) 2>&1
)"
fd_limit_rc=$?
set -e
[[ "${fd_limit_rc}" != 0 && "${fd_limit_error}" == *'resource_limit: nofile'* ]]

/usr/bin/python3 -I - "${metadata}" <<'PY'
import json,sys
doc=json.load(open(sys.argv[1],encoding="utf-8"))
assert doc["version"] == 3
assert doc["limits"]["max_records"] == 4096
assert doc["limits"]["max_file_bytes"] == 16 * 1024 * 1024 * 1024
assert doc["roots"] == ["/var/lib/pgw", "/etc/pgw/agent.token", "/srv/pgw-cache"]
paths={item["path"] for item in doc["records"]}
by_path={item["path"]:item for item in doc["records"]}
assert {"var", "var/lib", "etc", "etc/pgw"}.isdisjoint(paths)
assert "var/lib/pgw" in paths and "var/lib/pgw/rules/lkg.nft" in paths
assert "etc/pgw/agent.token" in paths
assert "srv/pgw-cache" in paths and "srv/pgw-cache/state" in paths
assert "var/lib/pgw/setgid-cache" in paths
assert "var/lib/pgw/sticky-cache" in paths
assert by_path["var/lib/pgw/setgid-cache"]["mode"] == 0o2750
assert by_path["var/lib/pgw/sticky-cache"]["mode"] == 0o1750
PY

assert_restored_metadata() {
    /usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" verify \
        "${snapshot}" restored "${live}"
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw")" == 2001:2001:750 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/pgw.db")" == 2002:2002:640 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/rules")" == 2003:2003:750 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/rules/lkg.nft")" == 2004:2004:600 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/etc/pgw/agent.token")" == 2005:2005:600 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/srv/pgw-cache")" == 2006:2006:710 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/srv/pgw-cache/state")" == 2007:2007:644 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/setgid-cache")" == 2008:2008:2750 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/setgid-cache/state")" == 2009:2009:640 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/sticky-cache")" == 2010:2010:1750 ]]
    [[ "$(stat -c '%u:%g:%a' "${live}/var/lib/pgw/sticky-cache/state")" == 2011:2011:640 ]]
    [[ "$(<"${live}/var/lib/pgw/pgw.db")" == api-state ]]
    [[ "$(<"${live}/var/lib/pgw/setgid-cache/state")" == setgid-state ]]
    [[ "$(<"${live}/var/lib/pgw/sticky-cache/state")" == sticky-state ]]
    [[ ! -e "${live}/etc/pgw/obsolete.secret" ]]
}

printf 'unsafe-old\n' >"${live}/var/lib/pgw/pgw.db"
rm -rf -- "${live}/var/lib/pgw/rules"
printf 'rotated\n' >"${live}/etc/pgw/agent.token"
chmod 0777 "${live}/srv/pgw-cache"
printf 'cache-mutation\n' >"${live}/srv/pgw-cache/state"
printf 'must-delete\n' >"${live}/etc/pgw/obsolete.secret"
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" "${metadata}" /var/lib/pgw 0
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present "${snapshot}/files/etc/pgw/agent.token" "${live}/etc/pgw/agent.token" "${metadata}" /etc/pgw/agent.token 0
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present "${snapshot}/files/srv/pgw-cache" "${live}/srv/pgw-cache" "${metadata}" /srv/pgw-cache 0
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" absent /dev/null "${live}/etc/pgw/obsolete.secret" "${metadata}" /etc/pgw/obsolete.secret 0
assert_restored_metadata

# Root directory metadata must be independent of the restorer's umask.  Each
# iteration corrupts both logical roots before exercising the real exchange.
for restore_umask in 000 022 077; do
    chmod 0777 "${live}/var/lib/pgw" "${live}/srv/pgw-cache"
    chmod 0755 "${live}/var/lib/pgw/setgid-cache" "${live}/var/lib/pgw/sticky-cache"
    printf 'umask-%s\n' "${restore_umask}" >"${live}/var/lib/pgw/pgw.db"
    printf 'umask-%s\n' "${restore_umask}" >"${live}/srv/pgw-cache/state"
    (
        umask "${restore_umask}"
        /usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present \
            "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" \
            "${metadata}" /var/lib/pgw 0
        /usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present \
            "${snapshot}/files/srv/pgw-cache" "${live}/srv/pgw-cache" \
            "${metadata}" /srv/pgw-cache 0
    )
    assert_restored_metadata
done

# Verification must reject a root-mode regression, not merely descendant drift.
chmod 0755 "${live}/var/lib/pgw"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" verify \
    "${snapshot}" restored "${live}" >/dev/null 2>&1
root_mode_verify_rc=$?
set -e
[[ "${root_mode_verify_rc}" != 0 ]]
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present \
    "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" \
    "${metadata}" /var/lib/pgw 0

# A concurrent rename after the file fd is opened must not let verification
# bless bytes from the old inode while the managed name points at an attacker
# replacement.  The production verifier re-checks the dirfd binding after hash.
install -d -m 0700 "${live}/swap-test/victim"
printf 'trusted-content\n' >"${live}/swap-test/victim/state"
printf 'attacker-content\n' >"${live}/swap-test/replacement"
chmod 0600 "${live}/swap-test/victim/state" "${live}/swap-test/replacement"
/usr/bin/python3 -I - "${ROOT}/deploy/restore_snapshot.py" "${live}/swap-test" <<'PY'
import hashlib, importlib.util, os, stat, sys, threading
module_path, parent_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("pgw_restore_swap", module_path)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
trusted = b"trusted-content\n"
root_info = os.stat(os.path.join(parent_path, "victim"), follow_symlinks=False)
file_info = os.stat(os.path.join(parent_path, "victim", "state"), follow_symlinks=False)
records = {
    "root": {"path":"root", "type":"dir", "mode":stat.S_IMODE(root_info.st_mode),
             "uid":root_info.st_uid, "gid":root_info.st_gid},
    "root/state": {"path":"root/state", "type":"file", "mode":stat.S_IMODE(file_info.st_mode),
                   "uid":file_info.st_uid, "gid":file_info.st_gid,
                   "size":file_info.st_size, "sha256":hashlib.sha256(trusted).hexdigest()},
}
opened = threading.Event(); swapped = threading.Event()
original_read = module.os.read
first = True
def guarded_read(fd, count):
    global first
    if first:
        first = False
        opened.set()
        if not swapped.wait(5):
            raise RuntimeError("swap thread did not run")
    return original_read(fd, count)
def attacker():
    if not opened.wait(5):
        return
    os.replace(os.path.join(parent_path, "replacement"),
               os.path.join(parent_path, "victim", "state"))
    swapped.set()
thread = threading.Thread(target=attacker)
thread.start()
parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    module.os.read = guarded_read
    assert not module.node_matches(parent, "victim", "root", records)
finally:
    module.os.read = original_read
    os.close(parent)
thread.join(5)
assert not thread.is_alive() and swapped.is_set()
assert open(os.path.join(parent_path, "victim", "state"), "rb").read() == b"attacker-content\n"

# Pause in the fixture wrapper after the child fd has been completely verified
# but before its result reaches the parent.  An in-place write keeps dev+ino and
# proves that the parent's full ctime/size/content identity fence is effective.
os.mkdir(os.path.join(parent_path, "inplace"), 0o700)
inplace_path = os.path.join(parent_path, "inplace", "state")
with open(inplace_path, "wb") as handle:
    handle.write(trusted)
os.chmod(inplace_path, 0o600)
root_info = os.stat(os.path.join(parent_path, "inplace"), follow_symlinks=False)
file_info = os.stat(inplace_path, follow_symlinks=False)
inplace_inode = (file_info.st_dev, file_info.st_ino)
inplace_records = {
    "root": {"path":"root", "type":"dir", "mode":stat.S_IMODE(root_info.st_mode),
             "uid":root_info.st_uid, "gid":root_info.st_gid},
    "root/state": {"path":"root/state", "type":"file", "mode":stat.S_IMODE(file_info.st_mode),
                   "uid":file_info.st_uid, "gid":file_info.st_gid,
                   "size":file_info.st_size, "sha256":hashlib.sha256(trusted).hexdigest()},
}
child_returned = threading.Event(); modified = threading.Event()
original_verify = module._opened_node_matches
def pause_after_child(parent_fd, name, relative, selected, held=None):
    result = original_verify(parent_fd, name, relative, selected, held)
    if relative == "root/state" and result is not None:
        child_returned.set()
        if not modified.wait(5):
            raise RuntimeError("in-place modifier did not run")
    return result
def modify_same_inode():
    if not child_returned.wait(5):
        return
    with open(inplace_path, "ab", buffering=0) as handle:
        handle.write(b"changed-in-place\n")
        os.fsync(handle.fileno())
    modified.set()
modifier = threading.Thread(target=modify_same_inode)
modifier.start()
parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    module._opened_node_matches = pause_after_child
    assert not module.node_matches(parent, "inplace", "root", inplace_records)
finally:
    module._opened_node_matches = original_verify
    os.close(parent)
modifier.join(5)
after_info = os.stat(inplace_path, follow_symlinks=False)
assert not modifier.is_alive() and modified.is_set()
assert (after_info.st_dev, after_info.st_ino) == inplace_inode
assert after_info.st_size > file_info.st_size
PY
rm -rf -- "${live}/swap-test"

# A post-exchange verification failure must retain the deterministic previous
# tree until the authenticated retry proves the restored target and cleans it.
printf 'pre-verify-failure\n' >"${live}/var/lib/pgw/pgw.db"
/usr/bin/python3 -I - "${ROOT}/deploy/restore_snapshot.py" \
    "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" "${metadata}" <<'PY'
import hashlib, importlib.util, os, stat, sys
module_path, source, target, metadata = sys.argv[1:]
spec = importlib.util.spec_from_file_location("pgw_restore_residue", module_path)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
original = module.node_matches
target_parent = os.path.dirname(target)
target_name = os.path.basename(target)
def fingerprint(path):
    records = []
    def visit(node, relative):
        info = os.lstat(node)
        item = (relative, stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                info.st_uid, info.st_gid, info.st_size, info.st_nlink)
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with open(node, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            records.append(item + (digest.hexdigest(),))
        elif stat.S_ISLNK(info.st_mode):
            records.append(item + (os.readlink(node),))
        elif stat.S_ISDIR(info.st_mode):
            children = sorted(os.listdir(node))
            records.append(item + (tuple(children),))
            for child in children:
                visit(os.path.join(node, child), relative + "/" + child)
        else:
            raise AssertionError("unexpected prior-tree node type")
    visit(path, ".")
    return tuple(records)
prior_fingerprint = fingerprint(target)
assert open(os.path.join(target, "pgw.db"), "rb").read() == b"pre-verify-failure\n"
def reject_exchanged(parent, name, relative, records):
    if name == target_name:
        return False
    return original(parent, name, relative, records)
module.node_matches = reject_exchanged
try:
    module.restore_posix("present", source, target, metadata, "/var/lib/pgw", 0)
except SystemExit as error:
    assert "exchanged restore tree failed" in str(error)
else:
    raise AssertionError("post-exchange verification failure was not propagated")
stage = module.deterministic_restore_name(metadata, "/var/lib/pgw", "stage")
stage_path = os.path.join(target_parent, stage)
assert os.path.lexists(stage_path)
assert fingerprint(stage_path) == prior_fingerprint
assert open(os.path.join(stage_path, "pgw.db"), "rb").read() == b"pre-verify-failure\n"

def require_exact_prior(candidate):
    if fingerprint(candidate) != prior_fingerprint:
        raise ValueError("retained stage fingerprint mismatch")
require_exact_prior(stage_path)
stage_db = os.path.join(stage_path, "pgw.db")
with open(stage_db, "rb") as handle:
    retained_db = handle.read()
with open(stage_db, "wb") as handle:
    handle.write(b"corrupt-retained-stage\n")
try:
    require_exact_prior(stage_path)
except ValueError:
    pass
else:
    raise AssertionError("corrupt retained stage was accepted")
with open(stage_db, "wb") as handle:
    handle.write(retained_db)
require_exact_prior(stage_path)

held_stage = stage_path + ".fixture-held"
os.rename(stage_path, held_stage)
os.mkdir(stage_path, 0o700)
try:
    try:
        require_exact_prior(stage_path)
    except ValueError:
        pass
    else:
        raise AssertionError("empty retained stage was accepted")
finally:
    os.rmdir(stage_path)
    os.rename(held_stage, stage_path)
require_exact_prior(stage_path)
module.node_matches = original
module.restore_posix("present", source, target, metadata, "/var/lib/pgw", 0)
assert not os.path.lexists(stage_path)
assert open(os.path.join(target, "pgw.db"), "rb").read() == b"api-state\n"
PY

cp "${snapshot}/manifest" "${snapshot}/manifest.valid"
printf 'present\t/var/lib/pgw/rules\n' >>"${snapshot}/manifest"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" metadata "${snapshot}" >/dev/null 2>&1
overlap_rc=$?
set -e
[[ "${overlap_rc}" != 0 ]]
mv -f -- "${snapshot}/manifest.valid" "${snapshot}/manifest"

# Kill the real production restore routine immediately after its atomic present
# exchange. Retry must recognize the authenticated target, remove the old stage,
# and leave no untracked residue.
printf 'crash-mutation\n' >"${live}/var/lib/pgw/pgw.db"
set +e
/usr/bin/python3 -I - "${ROOT}/deploy/restore_snapshot.py" \
    "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" "${metadata}" <<'PY'
import importlib.util,os,signal,sys
module_path,source,target,metadata=sys.argv[1:]
spec=importlib.util.spec_from_file_location("pgw_restore",module_path)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
original=module.exchange
def crash(parent,stage,target_name):
    original(parent,stage,target_name)
    os.kill(os.getpid(),signal.SIGKILL)
module.exchange=crash
module.restore_posix("present",source,target,metadata,"/var/lib/pgw",0)
PY
present_crash_rc=$?
set -e
[[ "${present_crash_rc}" == 137 ]]
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" "${metadata}" /var/lib/pgw 0
[[ "$(<"${live}/var/lib/pgw/pgw.db")" == api-state ]]

# Repeat at the absent-object rename boundary. The deterministic tombstone is
# derived from authenticated snapshot material, so startup retry can safely
# finish deletion without trusting a random path.
printf 'delete-after-crash\n' >"${live}/etc/pgw/obsolete.secret"
set +e
/usr/bin/python3 -I - "${ROOT}/deploy/restore_snapshot.py" \
    "${live}/etc/pgw/obsolete.secret" "${metadata}" <<'PY'
import importlib.util,os,signal,sys
module_path,target,metadata=sys.argv[1:]
spec=importlib.util.spec_from_file_location("pgw_restore",module_path)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
original=os.rename
def crash(source,destination,*args,**kwargs):
    original(source,destination,*args,**kwargs)
    if str(destination).startswith(".pgw-restore-tomb-"):
        os.kill(os.getpid(),signal.SIGKILL)
os.rename=crash
module.restore_posix("absent","/dev/null",target,metadata,"/etc/pgw/obsolete.secret",0)
PY
absent_crash_rc=$?
set -e
[[ "${absent_crash_rc}" == 137 ]]
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" absent /dev/null "${live}/etc/pgw/obsolete.secret" "${metadata}" /etc/pgw/obsolete.secret 0
[[ ! -e "${live}/etc/pgw/obsolete.secret" ]]
! find "${live}" -name '.pgw-restore-*' -print -quit | grep -q .

chown 2010:2010 "${snapshot}/files/var/lib/pgw/pgw.db"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present "${snapshot}/files/var/lib/pgw" "${live}/var/lib/pgw" "${metadata}" /var/lib/pgw 0 >/dev/null 2>&1
rc=$?
set -e
[[ "${rc}" != 0 && "$(<"${live}/var/lib/pgw/pgw.db")" == api-state ]]

printf 'snapshot logical-root ownership/atomic restore tests: PASS\n'
