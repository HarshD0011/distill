"""Generate macOS command and syscall catalogs from the local SDK and userland.

The output is syscall and command *names* plus Distill effect classes. It does
not copy Apple header text.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/"
    "Developer/SDKs/MacOSX.sdk/usr/include/sys/syscall.h"
)

READ_ONLY = {
    "ls", "cat", "echo", "printf", "pwd", "whoami", "id", "uname", "which",
    "whereis", "file", "stat", "wc", "head", "tail", "grep", "egrep", "fgrep",
    "cut", "sort", "uniq", "tr", "comm", "diff", "cmp", "basename", "dirname",
    "expr", "test", "[", "true", "false", "seq", "fold", "expand", "unexpand",
    "nl", "od", "hexdump", "xxd", "strings", "man", "apropos", "printenv",
    "logname", "groups", "tty", "uptime", "sw_vers", "hostname", "df", "du",
    "ps", "pgrep", "whatis", "locale", "cal", "factor", "jot", "look", "paste",
    "rs", "rev", "split", "csplit", "column", "tsort", "join", "pr", "fmt",
    "units", "bc", "dc", "banner", "who", "w", "last", "users", "finger",
    "vm_stat", "memory_pressure", "sysctl", "pagesize", "arch", "machine",
    "hostinfo", "uname", "pathchk", "cksum", "sum", "md5", "shasum", "openssl",
}
# openssl and sysctl can mutate. Remove those from read-only.
READ_ONLY -= {"openssl", "sysctl", "split", "csplit"}

FILE_WRITE = {
    "cp", "mv", "install", "tee", "ln", "link", "mkdir", "mkfifo", "mknod",
    "touch", "truncate", "ditto", "rsync", "strip", "codesign", "xattr",
    "chflags", "SetFile", "textutil", "sips", "iconv",
}
FILE_DELETE = {"rm", "rmdir", "unlink", "shred", "srm"}
NETWORK = {
    "curl", "wget", "nc", "netcat", "ping", "ping6", "dig", "host", "nslookup",
    "ftp", "telnet", "tftp", "traceroute", "traceroute6", "whois", "nc",
    "socat", "nscurl", "dscacheutil",
}
REMOTE_EXEC = {"ssh", "scp", "sftp", "rsync", "telnet"}
# rsync is both local write and remote. Remote wins if listed later; keep rsync as remote.
FILE_WRITE.discard("rsync")
EXECUTE = {
    "python", "python3", "perl", "ruby", "node", "php", "lua", "swift",
    "osascript", "jsc", "java", "javac", "open", "xcodebuild", "xcrun",
    "clang", "clang++", "gcc", "g++", "cc", "c++", "make", "npm", "pnpm",
    "yarn", "npx", "pip", "pip3", "gem", "cargo", "go", "swiftc",
}
PRIVILEGE = {"sudo", "su", "login", "doas"}
ARCHIVE = {
    "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2", "xz", "zipinfo",
    "compress", "uncompress", "cpio", "pax", "hdiutil", "pkgutil", "ditto",
}
FILE_WRITE.discard("ditto")
DEVICE = {
    "dd", "diskutil", "newfs", "newfs_apfs", "newfs_hfs", "mount", "umount",
    "mount_apfs", "mount_hfs", "asr", "bless", "nvram", "tmutil", "fdisk",
    "gpt", "pdisk",
}
SERVICE = {
    "launchctl", "systemctl", "shutdown", "reboot", "halt", "poweroff",
    "kickstart", "launchd", "ifconfig", "route", "arp", "ndp", "networksetup",
    "scutil", "ipconfig", "openssl",
}
PACKAGE = {
    "brew", "port", "installer", "softwareupdate", "pkgutil", "mas",
}
PACKAGE.discard("pkgutil")  # listed in archive; package is the stronger floor
SIGNAL = {"kill", "pkill", "killall", "renice", "nice"}

CLASSES = [
    ("read_only", READ_ONLY),
    ("file_write", FILE_WRITE),
    ("file_delete", FILE_DELETE),
    ("network", NETWORK - REMOTE_EXEC),
    ("remote_exec", REMOTE_EXEC),
    ("execute", EXECUTE),
    ("privilege", PRIVILEGE),
    ("archive", ARCHIVE),
    ("device", DEVICE),
    ("service", SERVICE),
    ("package", PACKAGE),
    ("signal", SIGNAL),
]

SYSCALL_CLASS = {
    "read": "read", "pread": "read", "readv": "read", "preadv": "read",
    "access": "read", "faccessat": "read", "stat": "read", "lstat": "read",
    "fstat": "read", "fstatat": "read", "getdirentries": "read",
    "getdirentries64": "read", "getattrlist": "read", "listxattr": "read",
    "getxattr": "read", "readlink": "read", "readlinkat": "read",
    "write": "write", "pwrite": "write", "writev": "write", "pwritev": "write",
    "open": "write", "openat": "write", "creat": "write", "truncate": "write",
    "ftruncate": "write", "mkdir": "write", "mkdirat": "write", "rename": "write",
    "renameat": "write", "link": "write", "linkat": "write", "symlink": "write",
    "symlinkat": "write", "copyfile": "write", "clonefileat": "write",
    "setattrlist": "write", "setxattr": "write", "removexattr": "write",
    "unlink": "delete", "unlinkat": "delete", "rmdir": "delete",
    "chmod": "perm", "fchmod": "perm", "fchmodat": "perm", "chown": "perm",
    "fchown": "perm", "lchown": "perm", "fchownat": "perm", "chflags": "perm",
    "fchflags": "perm",
    "execve": "exec", "posix_spawn": "exec",
    "connect": "net", "connectx": "net", "sendto": "net", "sendmsg": "net",
    "recvfrom": "net", "recvmsg": "net", "bind": "net", "listen": "net",
    "accept": "net", "socket": "net",
    "setuid": "priv", "setgid": "priv", "seteuid": "priv", "setegid": "priv",
    "setreuid": "priv", "setregid": "priv", "ptrace": "priv", "issetugid": "priv",
    "kill": "signal", "mprotect": "priv", "mmap": "write", "munmap": "write",
    "mount": "device", "unmount": "device", "fsctl": "device",
    "exit": "info", "fork": "info", "vfork": "info", "wait4": "info",
    "getpid": "info", "getuid": "info", "geteuid": "info", "getgid": "info",
    "getegid": "info", "getppid": "info", "close": "info", "dup": "info",
    "dup2": "info", "chdir": "info", "fchdir": "info", "getcwd": "info",
}


def bins():
    found = set()
    for directory in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
        if not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            if name.startswith(".") or "/" in name:
                continue
            found.add(name)
    return found


class Trie:
    def __init__(self):
        self.nodes = [{"edges": {}, "class": 0}]

    def insert(self, key, class_tag):
        index = 0
        for byte in key.encode():
            edges = self.nodes[index]["edges"]
            if byte not in edges:
                edges[byte] = len(self.nodes)
                self.nodes.append({"edges": {}, "class": 0})
            index = edges[byte]
        if self.nodes[index]["class"] == 0:
            self.nodes[index]["class"] = class_tag

    def emit(self):
        flat_edges = []
        rendered_nodes = []
        for node in self.nodes:
            start = len(flat_edges)
            for byte, child in sorted(node["edges"].items()):
                flat_edges.append((byte, child))
            rendered_nodes.append((start, len(node["edges"]), node["class"]))
        node_lines = ["const NODES: &[crate::trie::Node] = &["]
        for start, count, class_tag in rendered_nodes:
            node_lines.append(
                f"    crate::trie::Node {{ edge_start: {start}, edge_count: {count}, class: {class_tag} }},"
            )
        node_lines.append("];")
        edge_lines = ["const EDGES: &[crate::trie::Edge] = &["]
        for byte, child in flat_edges:
            edge_lines.append(f"    crate::trie::Edge {{ byte: {byte}, child: {child} }},")
        edge_lines.append("];")
        return "\n".join(node_lines + [""] + edge_lines)


def main():
    names = bins()
    assigned = set()
    command_tags = {
        "read_only": 1,
        "file_write": 2,
        "file_delete": 3,
        "network": 4,
        "remote_exec": 5,
        "execute": 6,
        "privilege": 7,
        "archive": 8,
        "device": 9,
        "service": 10,
        "package": 11,
        "signal": 12,
    }
    command_trie = Trie()
    for key, values in CLASSES:
        assigned |= set(values)
        for name in sorted(values):
            command_trie.insert(name, command_tags[key])
    unmodeled = names - assigned
    for name in sorted(unmodeled):
        command_trie.insert(name, 13)
    command_text = """// Generated by scripts/gen_macos_catalog.py. Do not edit by hand.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandClass {
    ReadOnly = 1,
    FileWrite = 2,
    FileDelete = 3,
    Network = 4,
    RemoteExec = 5,
    Execute = 6,
    Privilege = 7,
    Archive = 8,
    Device = 9,
    Service = 10,
    Package = 11,
    Signal = 12,
    Unmodeled = 13,
}

"""
    command_text += command_trie.emit()
    command_text += """

pub fn command_class(name: &str) -> Option<CommandClass> {
    match crate::trie::lookup(NODES, EDGES, name)? {
        1 => Some(CommandClass::ReadOnly),
        2 => Some(CommandClass::FileWrite),
        3 => Some(CommandClass::FileDelete),
        4 => Some(CommandClass::Network),
        5 => Some(CommandClass::RemoteExec),
        6 => Some(CommandClass::Execute),
        7 => Some(CommandClass::Privilege),
        8 => Some(CommandClass::Archive),
        9 => Some(CommandClass::Device),
        10 => Some(CommandClass::Service),
        11 => Some(CommandClass::Package),
        12 => Some(CommandClass::Signal),
        13 => Some(CommandClass::Unmodeled),
        _ => None,
    }
}
"""
    (ROOT / "crates/distill-interp/src/macos_commands.rs").write_text(command_text)

    syscalls = []
    for line in HEADER.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("#define") or "SYS_" not in line:
            continue
        parts = line.split()
        if len(parts) < 3 or not parts[1].startswith("SYS_"):
            continue
        syscalls.append(parts[1][4:])
    syscall_tags = {
        "read": 1, "write": 2, "delete": 3, "perm": 4, "exec": 5, "net": 6,
        "priv": 7, "signal": 8, "device": 9, "info": 10, "unmodeled": 11,
    }
    syscall_trie = Trie()
    known = set()
    for name in sorted(set(syscalls)):
        kind = SYSCALL_CLASS.get(name, "unmodeled")
        syscall_trie.insert(name, syscall_tags[kind])
        known.add(name)
    syscall_text = """// Generated by scripts/gen_macos_catalog.py. Names only; no header text.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallClass {
    Read = 1,
    Write = 2,
    Delete = 3,
    Perm = 4,
    Exec = 5,
    Net = 6,
    Priv = 7,
    Signal = 8,
    Device = 9,
    Info = 10,
    Unmodeled = 11,
}

"""
    syscall_text += syscall_trie.emit()
    syscall_text += """

pub fn syscall_class(name: &str) -> Option<SyscallClass> {
    match crate::trie::lookup(NODES, EDGES, name)? {
        1 => Some(SyscallClass::Read),
        2 => Some(SyscallClass::Write),
        3 => Some(SyscallClass::Delete),
        4 => Some(SyscallClass::Perm),
        5 => Some(SyscallClass::Exec),
        6 => Some(SyscallClass::Net),
        7 => Some(SyscallClass::Priv),
        8 => Some(SyscallClass::Signal),
        9 => Some(SyscallClass::Device),
        10 => Some(SyscallClass::Info),
        11 => Some(SyscallClass::Unmodeled),
        _ => None,
    }
}
"""
    syscall_text += f"\n#[allow(dead_code)]\npub const SYSCALL_COUNT: usize = {len(known)};\n"
    (ROOT / "crates/distill-interp/src/macos_syscalls.rs").write_text(syscall_text)
    print(f"commands {len(names)} unmodeled {len(unmodeled)} syscalls {len(known)}")


if __name__ == "__main__":
    main()
