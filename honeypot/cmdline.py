# Command Line Parser
# splits a line into segments joined by ;, && or || and each segment into a pipeline of stages
# one parser for every layer, so the store, the filters and Qwen agree on where a command ends
# constructs that are not emulated raise ParseError instead of being guessed

# Imports
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import re
import shlex

OPERATORS = ("2>>", "2>", ">>", "||", "&&", ">", "<", "|", ";", "&")
UNSUPPORTED_OPS = {"<", "2>", "2>>"}


# Raised when the line uses something that is not emulated
class ParseError(Exception):
    pass


@dataclass
class Stage:
    argv: list[str]
    raw: str
    # Shell Fields - filled by parse_shell, parse() leaves the defaults

    # Words with expansion markers, expanded when the segment runs
    words: Optional[list[str]] = None
    # Leading NAME=value assignments
    assignments: list[str] = field(default_factory=list)
    # Stderr target - None for the terminal, ("stdout",), ("same",) or (">" or ">>", path)
    stderr: Optional[tuple] = None
    # Set by >&2
    stdout_to_stderr: bool = False
    # Input file from < file
    stdin_path: Optional[str] = None
    # What Qwen and retrieval see when an alias changed argv
    model_argv: Optional[list[str]] = None


@dataclass
class Segment:
    stages: list[Stage]
    # How this segment follows the previous one - ;, && or ||
    joiner: str = ";"
    # Output redirect as ('>' or '>>', path)
    redirect: Optional[tuple[str, str]] = None
    raw: str = ""
    background: bool = False


# Split a line into ('word' or 'op', text) pairs
# honours quotes and backslashes
def tokenize(line: str, variables=None) -> list[tuple[str, str]]:
    variables = variables or {}
    def expand(text):
        return re.sub(r"\$([!$?])", lambda m: str(variables.get(m[1], m[0])), text)
    tokens: list[tuple[str, str]] = []
    buf: list[str] = []
    # The buffer came from quotes, so keep it even when empty
    quoted = False
    i, n = 0, len(line)

    def flush() -> None:
        nonlocal quoted
        if buf or quoted:
            tokens.append(("word", "".join(buf)))
            buf.clear()
            quoted = False

    while i < n:
        ch = line[i]

        if ch == "\\" and i + 1 < n:
            buf.append(line[i + 1])
            i += 2
            continue

        if ch in "'\"":
            close = line.find(ch, i + 1)
            if close == -1:
                raise ParseError("unterminated quote")
            inner = line[i + 1:close]
            if ch == '"' and ("$(" in inner or "`" in inner):
                raise ParseError("command substitution")
            buf.append(expand(inner) if ch == '"' else inner)
            quoted = True
            i = close + 1
            continue

        if ch == "$" and i + 1 < n and line[i+1] in "!$?" and line[i+1] in variables:
            buf.append(str(variables[line[i+1]]))
            i += 2
            continue

        if ch == "`":
            raise ParseError("command substitution")
        if ch == "$" and line.startswith("$(", i):
            raise ParseError("command substitution")
        if line.startswith("<<", i):
            raise ParseError("here-document")

        if ch.isspace():
            flush()
            i += 1
            continue

        for op in OPERATORS:
            if line.startswith(op, i):
                flush()
                tokens.append(("op", op))
                i += len(op)
                break
        else:
            buf.append(ch)
            i += 1

    flush()
    return tokens


# Parse a full command line into segments
# raises ParseError for anything that is not emulated
def parse(line: str, variables=None) -> list[Segment]:
    tokens = tokenize(line, variables)
    if not tokens:
        return []

    segments: list[Segment] = []
    stages: list[Stage] = []
    words: list[str] = []
    redirect: Optional[tuple[str, str]] = None
    joiner = ";"
    pending_redirect: Optional[str] = None

    def end_stage() -> None:
        if words:
            # Keep argument boundaries when a bound tool re-parses a stage
            # joining bare words would turn quoted text such as '%n|%s' into a pipeline
            # and would lose empty arguments and file names with spaces
            stages.append(Stage(argv=list(words), raw=shlex.join(words)))
            words.clear()

    def end_segment(next_joiner: str, background: bool = False) -> None:
        nonlocal redirect, joiner
        end_stage()
        if stages or redirect:
            segments.append(Segment(stages=list(stages), joiner=joiner,
                                    redirect=redirect, background=background,
                                    raw=" | ".join(s.raw for s in stages)))
        stages.clear()
        redirect = None
        joiner = next_joiner

    for kind, text in tokens:
        if kind == "word":
            if pending_redirect:
                redirect = (pending_redirect, text)
                pending_redirect = None
            else:
                words.append(text)
            continue

        if text in UNSUPPORTED_OPS:
            raise ParseError(f"unsupported operator {text!r}")
        if text in (">", ">>"):
            end_stage()
            pending_redirect = text
        elif text == "|":
            if redirect:
                raise ParseError("redirect before a pipe")
            end_stage()
        elif text in (";", "&&", "||", "&"):
            if not words and not stages:
                raise ParseError("missing command before operator")
            end_segment(";" if text == "&" else text, background=text == "&")

    if pending_redirect:
        raise ParseError("redirect with no target")
    end_segment(";")
    return segments


# Shell Mode Parsing
# parse() above serves tool validation and the answer policies
# the controller uses parse_shell(), which handles the redirections and expansions attackers type
# expansion waits until a segment runs, because cd, export and $? change values between segments
# markers inside words, never present in real input
#   \x00L<c>\x00 - a quoted or escaped character that stays literal
#   \x00V<U|Q><expr>\x00 - a parameter expansion, unquoted (U) or quoted (Q)
#   \x00T<spec>\x00 - a tilde prefix (~, ~user, ~+, ~-)

_PROTECT = set("*?[]{},~")
_FD_OPS = ("2>&1", "1>&2", "1>>", "2>>", "1>", "2>")
_SHELL_OPS = ("&>>", "&>", ">&2", ">>", "||", "&&", ">", "<", "|", ";", "&")
_TARGET_OPS = {">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>", "<"}
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
PARAM_FORM = re.compile(r"(#?)([A-Za-z_][A-Za-z0-9_]*|[0-9]|[@*#?$!-])(?:(:?[-=+?])(.*))?", re.S)
COMPOUND_WORDS = {"for", "while", "until", "if", "then", "elif", "else", "fi", "case",
                  "esac", "select", "function", "do", "done", "{", "}", "((", "[[", "]]",
                  "coproc", "time"}
MAX_BRACE_WORDS = 4096


def _protect(ch: str) -> str:
    return "\x00L" + ch + "\x00" if ch in _PROTECT else ch


# Read a $ expansion at line[i]
# returns (marker, next index), or (None, i) for a literal $
def _parameter(line: str, i: int, quoted: bool):
    mode = "Q" if quoted else "U"
    if i + 1 >= len(line):
        return None, i
    nxt = line[i + 1]
    if nxt == "(":
        raise ParseError("arithmetic expansion" if line.startswith("$((", i) else "command substitution")
    if nxt == "{":
        close = line.find("}", i + 2)
        if close == -1:
            raise ParseError("unterminated parameter expansion")
        expr = line[i + 2:close]
        if not expr or any(x in expr for x in ("${", "$(", "`", "\x00")):
            raise ParseError("nested parameter expansion")
        match = PARAM_FORM.fullmatch(expr)
        if not match or (match.group(1) and match.group(3)):
            raise ParseError("unsupported parameter expansion")
        return "\x00V" + mode + expr + "\x00", close + 1
    if nxt == "'":
        raise ParseError("ANSI-C quoting")
    if nxt == '"':
        return (None, i) if quoted else ("", i + 1)
    match = _NAME.match(line, i + 1)
    if match:
        return "\x00V" + mode + match.group(0) + "\x00", match.end()
    if nxt.isdigit() or nxt in "@*#?$!-":
        return "\x00V" + mode + nxt + "\x00", i + 2
    return None, i


def _tokenize_shell(line: str) -> list[tuple[str, str]]:
    if "\x00" in line:
        raise ParseError("NUL byte")
    tokens: list[tuple[str, str]] = []
    buf: list[str] = []
    quoted = False
    i, n = 0, len(line)

    def flush() -> None:
        nonlocal quoted
        if buf or quoted:
            tokens.append(("word", "".join(buf)))
            buf.clear()
            quoted = False

    while i < n:
        ch = line[i]
        if ch == "\\":
            if i + 1 < n:
                buf.append(_protect(line[i + 1]))
                i += 2
            else:
                buf.append("\\")
                i += 1
            continue
        if ch == "'":
            close = line.find("'", i + 1)
            if close == -1:
                raise ParseError("unterminated quote")
            buf.append("".join(_protect(c) for c in line[i + 1:close]))
            quoted = True
            i = close + 1
            continue
        if ch == '"':
            j, part = i + 1, []
            while j < n and line[j] != '"':
                c = line[j]
                if c == "\\" and j + 1 < n and line[j + 1] in '"\\$`':
                    part.append(_protect(line[j + 1]))
                    j += 2
                    continue
                if c == "`":
                    raise ParseError("command substitution")
                if c == "$":
                    marker, after = _parameter(line, j, True)
                    if marker is not None:
                        part.append(marker)
                        j = after
                        continue
                part.append(_protect(c))
                j += 1
            if j >= n:
                raise ParseError("unterminated quote")
            buf.append("".join(part))
            quoted = True
            i = j + 1
            continue
        if ch == "`":
            raise ParseError("command substitution")
        if ch == "$":
            marker, after = _parameter(line, i, False)
            if marker is not None:
                buf.append(marker)
                i = after
                continue
            buf.append("$")
            i += 1
            continue
        if line.startswith("<<", i) or line.startswith("<(", i) or line.startswith(">(", i):
            raise ParseError("here-document or process substitution")
        if line.startswith("|&", i):
            raise ParseError("unsupported operator '|&'")
        if ch == "#" and not buf and not quoted:
            # A comment runs to the end of the line
            break
        if ch == "~" and not buf and not quoted:
            j = i + 1
            while j < n and not line[j].isspace() and line[j] not in "/;|&<>()'\"\\$`":
                j += 1
            spec = line[i + 1:j]
            if spec in ("", "+", "-") or re.fullmatch(r"[a-z_][a-z0-9_.-]*\$?", spec):
                buf.append("\x00T" + spec + "\x00")
                i = j
                continue
        if ch.isspace():
            flush()
            i += 1
            continue
        matched = None
        if not buf and not quoted:
            matched = next((op for op in _FD_OPS if line.startswith(op, i)), None)
        if matched is None:
            matched = next((op for op in _SHELL_OPS if line.startswith(op, i)), None)
        if matched is not None:
            flush()
            tokens.append(("op", matched))
            i += len(matched)
            continue
        buf.append(ch)
        i += 1
    flush()
    return tokens


def _skip_marker(word: str, i: int) -> int:
    return word.index("\x00", i + 1) + 1


def _sequence(body: str):
    m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", body)
    if m:
        a, b = int(m[1]), int(m[2])
        step = abs(int(m[3])) if m[3] and int(m[3]) else 1
        width = max(len(m[1].lstrip("-")), len(m[2].lstrip("-")))
        pad = any(x.lstrip("-").startswith("0") and len(x.lstrip("-")) > 1 for x in (m[1], m[2]))
        values = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        if len(values) > MAX_BRACE_WORDS:
            raise ParseError("brace expansion too large")
        return [(f"{v:0{width + (v < 0)}d}" if pad else str(v)) for v in values]
    m = re.fullmatch(r"([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?", body)
    if m:
        a, b = ord(m[1]), ord(m[2])
        step = abs(int(m[3])) if m[3] and int(m[3]) else 1
        values = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [chr(v) for v in values]
    return None


# Bash brace expansion over unquoted braces
# for example {a,b}, {1..5} and x{,.bak}
def brace_expand(word: str, depth: int = 0) -> list[str]:
    if depth > 16 or "{" not in word:
        return [word]
    i, n = 0, len(word)
    while i < n:
        c = word[i]
        if c == "\x00":
            i = _skip_marker(word, i)
            continue
        if c == "{":
            j, nested, commas = i + 1, 0, []
            while j < n:
                cj = word[j]
                if cj == "\x00":
                    j = _skip_marker(word, j)
                    continue
                if cj == "{":
                    nested += 1
                elif cj == "}":
                    if nested == 0:
                        break
                    nested -= 1
                elif cj == "," and nested == 0:
                    commas.append(j)
                j += 1
            if j >= n:
                return [word]
            pre, post = word[:i], word[j + 1:]
            if commas:
                parts, start = [], i + 1
                for index in commas:
                    parts.append(word[start:index])
                    start = index + 1
                parts.append(word[start:j])
            else:
                parts = _sequence(word[i + 1:j])
            if parts is not None:
                out: list[str] = []
                for part in parts:
                    out.extend(brace_expand(pre + part + post, depth + 1))
                    if len(out) > MAX_BRACE_WORDS:
                        raise ParseError("brace expansion too large")
                return out
        i += 1
    return [word]


# Readable form of a marked word for logs and error messages
def strip_markers(word: str) -> str:
    def show(m):
        body = m.group(1)
        if body[0] == "L":
            return body[1:]
        if body[0] == "T":
            return "~" + body[1:]
        return "${" + body[2:] + "}" if not _NAME.fullmatch(body[2:]) else "$" + body[2:]
    return re.sub("\x00([^\x00]*)\x00", show, word)


# Parse a line for execution
# words keep their expansion markers in Stage.words
def parse_shell(line: str) -> list[Segment]:
    tokens: list[tuple[str, str]] = []
    for kind, text in _tokenize_shell(line):
        if kind == "word":
            tokens.extend(("word", w) for w in brace_expand(text))
        else:
            tokens.append((kind, text))
    if not tokens:
        return []

    segments: list[Segment] = []
    stages: list[Stage] = []
    words: list[str] = []
    redirs: list[tuple[str, Optional[str]]] = []
    seg_redirect: Optional[tuple[str, str]] = None
    joiner = ";"
    pending: Optional[str] = None

    def end_stage() -> None:
        nonlocal seg_redirect
        if not words and not redirs:
            return
        if seg_redirect is not None:
            raise ParseError("redirect before a pipe")
        fd1: tuple = ("default",)
        fd2: tuple = ("default",)
        stdin_path = None
        for op, target in redirs:
            if op in (">", "1>"):
                fd1 = ("file", ">", target)
            elif op in (">>", "1>>"):
                fd1 = ("file", ">>", target)
            elif op == "2>":
                fd2 = ("file", ">", target)
            elif op == "2>>":
                fd2 = ("file", ">>", target)
            elif op in ("&>", "&>>"):
                fd1 = fd2 = ("file", op[1:], target)
            elif op == "2>&1":
                fd2 = fd1 if fd1[0] == "file" else ("stdout",)
            elif op in ("1>&2", ">&2"):
                fd1 = fd2 if fd2[0] == "file" else ("stderr",)
            elif op == "<":
                stdin_path = target
        assignments = []
        while words and _ASSIGN.match(words[0]):
            assignments.append(words.pop(0))
        if words:
            head = words[0]
            if (head in COMPOUND_WORDS or head.startswith("(") or head.endswith("()")
                    or (len(words) > 1 and words[1].startswith("()"))):
                raise ParseError("compound command")
        if fd2[0] == "file":
            stderr = ("same",) if fd1 == fd2 else (fd2[1], fd2[2])
        elif fd2[0] == "stdout":
            stderr = ("stdout",)
        else:
            stderr = None
        stage = Stage(argv=[], raw=" ".join(strip_markers(w) for w in words),
                      words=list(words), assignments=assignments, stderr=stderr,
                      stdout_to_stderr=fd1[0] == "stderr", stdin_path=stdin_path)
        stages.append(stage)
        if fd1[0] == "file":
            seg_redirect = (fd1[1], fd1[2])
        words.clear()
        redirs.clear()

    def end_segment(next_joiner: str, background: bool = False) -> None:
        nonlocal seg_redirect, joiner
        end_stage()
        if stages:
            segments.append(Segment(stages=list(stages), joiner=joiner, redirect=seg_redirect,
                                    background=background,
                                    raw=" | ".join(s.raw for s in stages)))
        stages.clear()
        seg_redirect = None
        joiner = next_joiner

    for kind, text in tokens:
        if kind == "word":
            if pending:
                redirs.append((pending, text))
                pending = None
            else:
                words.append(text)
            continue
        if pending:
            raise ParseError("redirect with no target")
        if text in _TARGET_OPS:
            pending = text
        elif text in ("2>&1", "1>&2", ">&2"):
            redirs.append((text, None))
        elif text == "|":
            if not words and not redirs:
                raise ParseError("missing command before pipe")
            end_stage()
        elif text in (";", "&&", "||", "&"):
            if not words and not redirs and not stages:
                raise ParseError("missing command before operator")
            end_segment(";" if text == "&" else text, background=text == "&")
    if pending:
        raise ParseError("redirect with no target")
    end_segment(";")
    if segments and segments[-1].joiner in ("&&", "||") and not segments[-1].stages:
        raise ParseError("dangling operator")
    return segments
