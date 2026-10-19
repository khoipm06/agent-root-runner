"""4-Stage Lexical & AST Shell Command Parser.

Part of Milestone 2 (M2) of Agent Root Runner.
Decomposes command chains, strips quotes/escapes, extracts redirections,
unwraps wrappers (sudo, sh -c, bash -c, eval, env, setsid, chroot, su),
inspects subshells, and detects pipe-to-shell stream evasions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
import shlex
from typing import Dict, List, Optional, Tuple

SHELL_INTERPRETERS: frozenset[str] = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "node", "php",
})

DESTRUCTIVE_COMMANDS: frozenset[str] = frozenset({
    "dd", "rm", "unlink", "mkfs", "mke2fs", "wipefs",
    "fdisk", "gdisk", "sfdisk", "sgdisk", "parted", "blkdiscard", "shred",
    "chmod", "chown", "chgrp", "sed", "truncate", "mv", "cp", "install", "tee",
    "find",
})

WRAPPER_COMMANDS: frozenset[str] = frozenset({
    "sudo", "doas", "env", "nohup", "nice",
    "ionice", "time", "exec", "stdbuf", "xargs", "pkexec", "setsid",
    # Shell keywords/builtins that prefix (and thus hide) the real command.
    "command", "builtin", "nocorrect",
})


def has_inplace_flag(args: List[str]) -> bool:
    """True if args contain an in-place edit flag (e.g. -i, -ni, --in-place)."""
    for a in args:
        if a == "--in-place":
            return True
        if a.startswith("-") and not a.startswith("--") and "i" in a[1:]:
            return True
    return False

FORK_BOMB_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    re.compile(r":\s*\(\s*\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;\s*:"),
    re.compile(r"(?:function\s+)?(\w+)\s*(?:\(\s*\))?\s*\{\s*(?:\1\s*\|\s*\1\s*&|[^}]*\|[^}]*&[^}]*)\s*\}\s*;\s*\1"),
    re.compile(r"\bfunction\s+\w+\s*(?:\(\s*\))?\s*\{.*\|.*&.*\}\s*;\s*\w+"),
)

REDIRECTION_OPERATORS: Tuple[str, ...] = (
    ">>", ">|", "1>>", "2>>", "&>", ">&", ">", "1>", "2>",
)


@dataclass(frozen=True)
class Redirection:
    """Represents a shell stream redirection."""
    operator: str
    target: str


@dataclass
class ParsedCommand:
    """Structured representation of an atomic parsed command node."""
    raw_str: str
    tokens: List[str]
    executable: str
    args: List[str]
    env_vars: Dict[str, str]
    redirections: List[Redirection]
    subshells: List[str]
    has_unresolved_var: bool = False
    is_pipe_to_shell: bool = False
    is_fork_bomb: bool = False
    has_syntax_error: bool = False
    unwrapped_commands: List["ParsedCommand"] = field(default_factory=list)
    is_xargs_critical_dataflow: bool = False


def split_command_chain(cmd_str: str) -> Tuple[List[Tuple[str, str]], bool]:
    """Stage 1: Operator decomposition outside quotes and subshells."""
    segments: List[Tuple[str, str]] = []
    current: List[str] = []
    quote: Optional[str] = None
    paren_depth: int = 0
    i = 0
    n = len(cmd_str)
    last_op = ";"
    has_syntax_error = False

    while i < n:
        c = cmd_str[i]

        if quote:
            current.append(c)
            if c == quote:
                if quote == '"' and i > 0 and cmd_str[i - 1] == '\\':
                    pass
                else:
                    quote = None
            i += 1
            continue

        if c in ("'", '"'):
            quote = c
            current.append(c)
            i += 1
            continue

        if c == '$' and i + 1 < n and cmd_str[i + 1] == '(':
            paren_depth += 1
            current.append("$(")
            i += 2
            continue

        if c == '(' and paren_depth > 0:
            paren_depth += 1
            current.append(c)
            i += 1
            continue

        if c == ')' and paren_depth > 0:
            paren_depth -= 1
            current.append(c)
            i += 1
            continue

        if paren_depth == 0 and c == '#':
            if i == 0 or cmd_str[i - 1].isspace():
                while i < n and cmd_str[i] != '\n':
                    i += 1
                if i < n and cmd_str[i] == '\n':
                    seg = "".join(current).strip()
                    if seg:
                        segments.append((last_op, seg))
                    last_op = "\n"
                    current = []
                    i += 1
                continue

        if paren_depth == 0:
            if i + 1 < n and cmd_str[i : i + 2] in ("&&", "||", "|&"):
                op = cmd_str[i : i + 2]
                seg = "".join(current).strip()
                if seg:
                    segments.append((last_op, seg))
                last_op = op
                current = []
                i += 2
                continue

            if c in (";", "\n", "|", "&"):
                op = c
                seg = "".join(current).strip()
                if seg:
                    segments.append((last_op, seg))
                last_op = op
                current = []
                i += 1
                continue

        current.append(c)
        i += 1

    if quote is not None or paren_depth != 0:
        has_syntax_error = True

    seg = "".join(current).strip()
    if seg:
        segments.append((last_op, seg))

    return segments, has_syntax_error


def extract_redirections_and_tokens(
    raw_cmd: str,
) -> Tuple[List[str], List[Redirection], bool]:
    """Stage 2: Extracts redirections and tokens with POSIX dequoting."""
    has_syntax_error = False
    try:
        lexer = shlex.shlex(raw_cmd, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        raw_tokens = list(lexer)
    except Exception:
        has_syntax_error = True
        raw_tokens = raw_cmd.split()

    tokens: List[str] = []
    redirections: List[Redirection] = []

    i = 0
    while i < len(raw_tokens):
        token = raw_tokens[i]
        matched_op: Optional[str] = None
        target: Optional[str] = None

        for op in REDIRECTION_OPERATORS:
            if token == op:
                matched_op = op
                if i + 1 < len(raw_tokens):
                    target = raw_tokens[i + 1]
                    i += 1
                break
            elif token.startswith(op) and len(token) > len(op):
                matched_op = op
                target = token[len(op):]
                break

        if matched_op and target:
            redirections.append(Redirection(operator=matched_op, target=target))
        else:
            tokens.append(token)
        i += 1

    return tokens, redirections, has_syntax_error


def extract_subshells(raw_cmd: str) -> List[str]:
    """Stage 4: Extracts command substitution subshells $(...), <(...), >(...), and `...`."""
    subshells: List[str] = []
    for prefix in ("$(", "<(", ">("):
        idx = 0
        while True:
            pos = raw_cmd.find(prefix, idx)
            if pos == -1:
                break
            depth = 1
            j = pos + len(prefix)
            while j < len(raw_cmd) and depth > 0:
                if raw_cmd[j] == '(':
                    depth += 1
                elif raw_cmd[j] == ')':
                    depth -= 1
                j += 1
            if depth == 0:
                subshells.append(raw_cmd[pos + len(prefix) : j - 1])
            idx = j

    backticks = re.findall(r"`([^`]+)`", raw_cmd)
    subshells.extend(backticks)
    return subshells


def _unwrap_command(parsed: ParsedCommand, depth: int = 0) -> None:
    """Stage 3: Recursively unwraps wrappers (sudo, sh -c, bash -c, eval, env, setsid, chroot, su)."""
    if depth > 10:
        return

    exe = parsed.executable
    args = parsed.args

    # Shell wrapper: bash -c, sh -c, bash -lc, sh -ec, bash -c --, python -c, perl -e
    if exe in SHELL_INTERPRETERS:
        c_flag_found = False
        c_idx = -1
        for i, arg in enumerate(args):
            if arg in ("-c", "-e"):
                c_flag_found = True
                c_idx = i
                break
            if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1 and (
                "c" in arg[1:] or (exe in ("perl", "ruby", "node") and "e" in arg[1:])
            ):
                c_flag_found = True
                c_idx = i
                break
        if c_flag_found and c_idx >= 0:
            k = c_idx + 1
            if k < len(args) and args[k] == "--":
                k += 1
            if k < len(args):
                inner_cmd = args[k]
                parsed.unwrapped_commands.extend(parse_command_chain(inner_cmd))
                return

    # Eval wrapper
    if exe == "eval":
        inner_cmd = " ".join(args)
        if inner_cmd.strip():
            parsed.unwrapped_commands.extend(parse_command_chain(inner_cmd))
            return

    # Chroot wrapper
    if exe == "chroot":
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-u", "-g", "-G", "--userspec", "--groups") and i + 1 < len(args):
                i += 2
                continue
            if arg == "--":
                i += 1
                if i + 1 < len(args):
                    wrapped_tokens = args[i + 1:]
                    wrapped_str = " ".join(shlex.quote(a) for a in wrapped_tokens)
                    parsed.unwrapped_commands.extend(parse_command_chain(wrapped_str))
                else:
                    parsed.unwrapped_commands.extend(parse_command_chain("/bin/sh"))
                return
            if arg.startswith("-"):
                i += 1
                continue
            wrapped_tokens = args[i + 1:]
            if wrapped_tokens:
                wrapped_str = " ".join(shlex.quote(a) for a in wrapped_tokens)
                parsed.unwrapped_commands.extend(parse_command_chain(wrapped_str))
            else:
                parsed.unwrapped_commands.extend(parse_command_chain("/bin/sh"))
            return

    # Su wrapper
    if exe == "su":
        inner_cmd = None
        for i, a in enumerate(args):
            if a in ("-c", "--command") and i + 1 < len(args):
                inner_cmd = args[i + 1]
                break
            elif a.startswith("--command="):
                inner_cmd = a.split("=", 1)[1]
                break
            elif a.startswith("-") and not a.startswith("--") and "c" in a[1:] and i + 1 < len(args):
                inner_cmd = args[i + 1]
                break
        if inner_cmd is not None:
            parsed.unwrapped_commands.extend(parse_command_chain(inner_cmd))
            return
        else:
            parsed.unwrapped_commands.extend(parse_command_chain("/bin/sh"))
            return

    # Busybox multicall wrapper: busybox <applet> <args...>
    if exe == "busybox":
        inner_cmd = " ".join(shlex.quote(a) for a in args)
        if inner_cmd.strip():
            parsed.unwrapped_commands.extend(parse_command_chain(inner_cmd))
        return

    # Sudo / env / nohup / nice / execution wrappers
    if exe in WRAPPER_COMMANDS:
        i = 0
        while i < len(args):
            arg = args[i]
            if (
                arg in ("-u", "-g", "-n", "-C", "-D", "-p", "--user", "--group")
                or (exe == "ionice" and arg == "-c")
            ) and i + 1 < len(args):
                i += 2
                continue
            if arg == "--":
                i += 1
                wrapped_tokens = args[i:]
                if wrapped_tokens:
                    wrapped_str = " ".join(shlex.quote(a) for a in wrapped_tokens)
                    parsed.unwrapped_commands.extend(parse_command_chain(wrapped_str))
                break
            if arg.startswith("-"):
                i += 1
                continue
            if "=" in arg and exe == "env":
                i += 1
                continue
            wrapped_tokens = args[i:]
            if wrapped_tokens:
                wrapped_str = " ".join(shlex.quote(a) for a in wrapped_tokens)
                parsed.unwrapped_commands.extend(parse_command_chain(wrapped_str))
            break


def _substitute_env_vars(token: str, env_vars: Dict[str, str]) -> str:
    """Substitutes $VAR and ${VAR} occurrences using defined env_vars."""
    if not env_vars:
        return token
    def repl(m: re.Match[str]) -> str:
        var = m.group(1) or m.group(2)
        return env_vars.get(var, m.group(0))
    return re.sub(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))", repl, token)


def parse_atomic_command(raw_str: str) -> ParsedCommand:
    """Parses a single atomic command segment into a ParsedCommand node."""
    tokens, redirs, lexer_syntax_error = extract_redirections_and_tokens(raw_str)
    subshells = extract_subshells(raw_str)

    env_vars: Dict[str, str] = {}
    cmd_tokens: List[str] = []
    idx = 0
    while idx < len(tokens):
        t = tokens[idx]
        if "=" in t and not cmd_tokens:
            k, v = t.split("=", 1)
            env_vars[k] = v
        else:
            cmd_tokens.append(t)
        idx += 1

    substituted_cmd_tokens = [_substitute_env_vars(t, env_vars) for t in cmd_tokens]
    substituted_redirs = [
        Redirection(operator=r.operator, target=_substitute_env_vars(r.target, env_vars))
        for r in redirs
    ]

    # Strip leading shell negation keywords ("!"), which otherwise become the
    # classified executable and hide the real destructive command.
    while substituted_cmd_tokens and substituted_cmd_tokens[0] == "!":
        substituted_cmd_tokens = substituted_cmd_tokens[1:]

    executable = ""
    args: List[str] = []
    if substituted_cmd_tokens:
        executable = os.path.basename(substituted_cmd_tokens[0])
        args = substituted_cmd_tokens[1:]

    is_fork_bomb = any(r.search(raw_str) for r in FORK_BOMB_PATTERNS)

    is_destr = (executable in DESTRUCTIVE_COMMANDS) or executable.startswith("mkfs")
    has_unres_var = False
    if is_destr:
        for t in substituted_cmd_tokens:
            if re.search(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))", t):
                has_unres_var = True
                break

    if not has_unres_var:
        for r in substituted_redirs:
            if re.search(r"\$(?:\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))", r.target):
                has_unres_var = True
                break

    parsed = ParsedCommand(
        raw_str=raw_str,
        tokens=substituted_cmd_tokens,
        executable=executable,
        args=args,
        env_vars=env_vars,
        redirections=substituted_redirs,
        subshells=subshells,
        has_unresolved_var=has_unres_var,
        is_fork_bomb=is_fork_bomb,
        has_syntax_error=lexer_syntax_error,
    )

    _unwrap_command(parsed)
    return parsed


def _is_shell_interpreter(cmd: ParsedCommand) -> bool:
    """Checks whether the command or its unwrapped targets execute a shell interpreter."""
    if cmd.executable in SHELL_INTERPRETERS:
        return True
    for unwrapped in cmd.unwrapped_commands:
        if _is_shell_interpreter(unwrapped):
            return True
    return False


XARGS_MUTATORS: frozenset[str] = frozenset({
    "rm", "unlink", "shred", "chmod", "chown", "chgrp", "chattr",
    "truncate", "mv", "dd", "wipefs", "tee", "cp", "install", "sed",
})

CRITICAL_PATH_ROOTS: frozenset[str] = frozenset({
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
    "/var", "/root", "/sysroot", "/opt", "/home",
})


def _is_critical_path(path: str) -> bool:
    """True if path is (or is under) a critical system root."""
    if not path.startswith("/"):
        return False
    norm = os.path.normpath(path)
    for root in CRITICAL_PATH_ROOTS:
        if norm == root or (root != "/" and norm.startswith(root + "/")):
            return True
    return False


def _has_recursive_flag(argv: List[str]) -> bool:
    for a in argv:
        if a in ("-r", "-R", "--recursive"):
            return True
        if a.startswith("-") and not a.startswith("--") and (
            "r" in a[1:] or "R" in a[1:]
        ):
            return True
    return False


def _xargs_critical_dataflow(
    producer: ParsedCommand, xargs_cmd: ParsedCommand
) -> bool:
    """Judge `PRODUCER | xargs MUTATOR` for critical-path dataflow.

    Critical literal paths from echo/printf or a critical `find` root always
    block; an unscoped/unknown producer blocks only for recursive mutators;
    producers scoped under /tmp never block.
    """
    if not xargs_cmd.unwrapped_commands:
        return False
    mutator = xargs_cmd.unwrapped_commands[0]
    if mutator.executable not in XARGS_MUTATORS:
        return False

    if producer.executable in ("echo", "printf"):
        return any(a.startswith("/") and _is_critical_path(a) for a in producer.args)

    if producer.executable == "find":
        root = next((a for a in producer.args if not a.startswith("-")), None)
        return root is not None and _is_critical_path(root)

    # Unknown/unscoped producer (e.g. `ls`): only recursive mutators are fatal.
    return _has_recursive_flag(mutator.args)


def parse_command_chain(cmd_str: str) -> List[ParsedCommand]:
    """Top-level entrypoint: parses command chain into a list of ParsedCommand nodes."""
    stripped = cmd_str.strip()
    if not stripped:
        return []

    segments, split_syntax_error = split_command_chain(stripped)
    parsed_list: List[ParsedCommand] = []

    for idx, (op, seg) in enumerate(segments):
        cmd = parse_atomic_command(seg)
        if split_syntax_error:
            cmd.has_syntax_error = True
        # Stage 4: Detect pipe-to-shell stream evasion (unwrapping targets)
        if op in ("|", "|&") and idx > 0:
            if _is_shell_interpreter(cmd):
                cmd.is_pipe_to_shell = True
            # Stage 5: PRODUCER | xargs MUTATOR critical-path dataflow
            if cmd.executable == "xargs" and _xargs_critical_dataflow(
                parsed_list[-1], cmd
            ):
                cmd.is_xargs_critical_dataflow = True
        parsed_list.append(cmd)

    return parsed_list
