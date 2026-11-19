# GNU Option Tables
# coreutils 8.32 options as shipped with Ubuntu 22.04
# used when no native handler implements a command form, in either routing mode
# an option GNU rejects gets GNU's exact message without a model call
# a valid option that is simply not implemented goes to the grounded model path instead

# Imports
from __future__ import annotations

from typing import Optional

# Each entry - command: (short options without an argument, short options taking one, long options)
TABLES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "ls": ("aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1", "ITw",
           ("all", "almost-all", "author", "escape", "block-size", "ignore-backups", "color",
            "directory", "dired", "classify", "file-type", "format", "full-time",
            "group-directories-first", "no-group", "human-readable", "si",
            "dereference-command-line", "dereference-command-line-symlink-to-dir", "hide",
            "hyperlink", "indicator-style", "inode", "ignore", "kibibytes", "dereference",
            "literal", "numeric-uid-gid", "hide-control-chars", "show-control-chars",
            "quote-name", "quoting-style", "reverse", "recursive", "size", "sort", "time",
            "time-style", "tabsize", "width", "context", "help", "version")),
    "cat": ("AbeEnstTuv", "",
            ("show-all", "number-nonblank", "show-ends", "number", "squeeze-blank", "show-tabs",
             "show-nonprinting", "help", "version")),
    "cp": ("abdfHilLnPpRrsuvxZT", "St",
           ("archive", "attributes-only", "backup", "copy-contents", "force", "interactive", "link",
            "dereference", "no-clobber", "no-dereference", "preserve", "no-preserve", "parents",
            "recursive", "reflink", "remove-destination", "sparse", "strip-trailing-slashes",
            "symbolic-link", "suffix", "target-directory", "no-target-directory", "update",
            "verbose", "one-file-system", "context", "help", "version")),
    "mv": ("bfinTuvZ", "St",
           ("backup", "force", "interactive", "no-clobber", "strip-trailing-slashes", "suffix",
            "target-directory", "no-target-directory", "update", "verbose", "context", "help",
            "version")),
    "rm": ("dfiIrRv", "",
           ("force", "interactive", "one-file-system", "no-preserve-root", "preserve-root",
            "recursive", "dir", "verbose", "help", "version")),
    "mkdir": ("pvZ", "m", ("mode", "parents", "verbose", "context", "help", "version")),
    "rmdir": ("pv", "", ("ignore-fail-on-non-empty", "parents", "verbose", "help", "version")),
    "touch": ("acfhm", "drt", ("no-create", "date", "no-dereference", "reference", "time", "help",
                               "version")),
    "ln": ("bdfFiLnPrsTv", "St",
           ("backup", "directory", "force", "interactive", "logical", "no-dereference", "physical",
            "relative", "symbolic", "suffix", "target-directory", "no-target-directory", "verbose",
            "help", "version")),
    "chown": ("cfhvRHLP", "",
              ("changes", "dereference", "no-dereference", "from", "no-preserve-root",
               "preserve-root", "silent", "quiet", "reference", "recursive", "verbose", "help",
               "version")),
    "chgrp": ("cfhvRHLP", "",
              ("changes", "dereference", "no-dereference", "no-preserve-root", "preserve-root",
               "silent", "quiet", "reference", "recursive", "verbose", "help", "version")),
    "head": ("qvz", "cn", ("bytes", "lines", "quiet", "silent", "verbose", "zero-terminated", "help",
                           "version")),
    "tail": ("fFqvz", "cns", ("bytes", "follow", "lines", "max-unchanged-stats", "pid", "quiet",
                              "retry", "silent", "sleep-interval", "verbose", "zero-terminated",
                              "help", "version")),
    "wc": ("clmwL", "", ("bytes", "chars", "lines", "files0-from", "max-line-length", "words",
                         "help", "version")),
    "stat": ("LftZ", "c", ("dereference", "file-system", "format", "printf", "terse", "cached",
                           "help", "version")),
    "du": ("0abcDhHklLmPsSx", "BdtX",
           ("null", "all", "apparent-size", "block-size", "bytes", "total", "dereference-args",
            "max-depth", "files0-from", "human-readable", "inodes", "dereference", "count-links",
            "no-dereference", "separate-dirs", "si", "summarize", "threshold", "time",
            "time-style", "exclude-from", "exclude", "one-file-system", "help", "version")),
    "df": ("ahHiklmPTv", "BFtx",
           ("all", "block-size", "human-readable", "si", "inodes", "local", "output", "portability",
            "print-type", "sync", "no-sync", "total", "type", "exclude-type", "help", "version")),
}
EXIT_STATUS = {"ls": 2}


def _long_known(command: str, option: str) -> bool:
    name = option[2:].split("=", 1)[0]
    longs = TABLES[command][2]
    return name in longs or sum(1 for long in longs if long.startswith(name)) == 1


# GNU's message for the first option GNU itself rejects, otherwise None
def invalid_option(argv: list[str]) -> Optional[tuple[str, int]]:
    if not argv:
        return None
    command = argv[0].rsplit("/", 1)[-1]
    if command not in TABLES:
        return None
    # GNU prints the name it was invoked as - /bin/ls --foo gives "/bin/ls: ..."
    program = argv[0]
    plain, valued, _ = TABLES[command]
    status = EXIT_STATUS.get(command, 1)
    args, index = argv[1:], 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            break
        if arg.startswith("--"):
            name = arg[2:].split("=", 1)[0]
            longs = TABLES[command][2]
            candidates = [long for long in longs if long.startswith(name)]
            if name not in longs and len(candidates) > 1:
                options = " ".join(f"'--{c}'" for c in candidates)
                return (f"{program}: option '--{name}' is ambiguous; possibilities: {options}\n"
                        f"Try '{program} --help' for more information.\n", status)
            if not _long_known(command, arg):
                return (f"{program}: unrecognized option '{arg}'\n"
                        f"Try '{program} --help' for more information.\n", status)
            continue
        if not arg.startswith("-") or arg == "-":
            continue
        if command in ("head", "tail") and arg[1:].rstrip("bkm").isdigit():
            # The obsolete -NUM form, still accepted by coreutils 8.32
            continue
        for position, flag in enumerate(arg[1:], 1):
            if flag in valued:
                if position == len(arg) - 1:
                    if index >= len(args):
                        return (f"{program}: option requires an argument -- '{flag}'\n"
                                f"Try '{program} --help' for more information.\n", status)
                    index += 1
                break
            if flag not in plain:
                return (f"{program}: invalid option -- '{flag}'\n"
                        f"Try '{program} --help' for more information.\n", status)
    return None
