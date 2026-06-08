import os
import shlex
from datetime import datetime

from flask import Flask, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# Virtual filesystem: a nested dict where directories are dicts and files are strings.
VFS = {
    "home": {
        "analyst": {
            "Desktop": {},
            "Documents": {
                "notes.txt": "SOC shift notes:\n- Review SIEM alerts every hour\n- Escalate anything tagged 'critical'\n",
                "playbook.md": "# Incident Response Playbook\n1. Identify\n2. Contain\n3. Eradicate\n4. Recover\n5. Lessons learned\n",
            },
            "logs": {
                "auth.log": (
                    "Jun 08 09:12:01 server sshd[1023]: Failed password for root from 203.0.113.5 port 51422 ssh2\n"
                    "Jun 08 09:12:03 server sshd[1023]: Failed password for root from 203.0.113.5 port 51423 ssh2\n"
                    "Jun 08 09:12:07 server sshd[1023]: Accepted password for analyst from 198.51.100.7 port 51500 ssh2\n"
                    "Jun 08 09:30:44 server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/systemctl status sshd\n"
                ),
                "syslog": (
                    "Jun 08 08:00:00 server systemd[1]: Started Daily apt download activities.\n"
                    "Jun 08 08:15:22 server kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.23 DST=10.0.0.5 PROTO=TCP DPT=23\n"
                    "Jun 08 08:42:09 server kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.99 DST=10.0.0.5 PROTO=TCP DPT=3389\n"
                ),
            },
            ".bash_history": "ls -la\ncd logs\ngrep 'Failed password' auth.log\ncat syslog | grep BLOCK\n",
            "readme.txt": (
                "Welcome to the SOC analyst practice terminal!\n\n"
                "Try commands like: ls, cd, pwd, cat, grep, less, find, whoami,\n"
                "ps, netstat, history, head, tail, wc, echo, clear, help\n"
            ),
        }
    },
    "var": {
        "log": {
            "auth.log": "Jun 08 09:12:01 server sshd[1023]: Failed password for root from 203.0.113.5 port 51422 ssh2\n",
        }
    },
    "etc": {
        "passwd": "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000:SOC Analyst:/home/analyst:/bin/bash\n",
        "hostname": "soc-trainer\n",
    },
}

HOME_PATH = ["home", "analyst"]
HOSTNAME = "soc-trainer"
USERNAME = "analyst"

FAKE_PROCESSES = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169000 11904 ?        Ss   08:00   0:02 /sbin/init
root       512  0.0  0.2  72308  9112 ?        Ss   08:00   0:00 /usr/sbin/sshd -D
root       744  0.0  0.3 256892 14220 ?        Ssl  08:00   0:05 /usr/bin/dockerd
analyst   2031  0.1  0.4  34560 18204 pts/0    Ss   09:10   0:01 -bash
analyst   2199  0.0  0.1  37364  3392 pts/0    R+   09:31   0:00 ps aux
"""

FAKE_NETSTAT = """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 10.0.0.5:22             198.51.100.7:51500      ESTABLISHED
tcp        0      0 10.0.0.5:443            203.0.113.20:61220      TIME_WAIT
tcp        0      0 10.0.0.5:23             198.51.100.23:50112     SYN_RECV
"""


def get_node(path_parts):
    node = VFS
    for part in path_parts:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def normalize_path(cwd_parts, target):
    if target.startswith("/"):
        parts = []
        target = target[1:]
    elif target in ("~", ""):
        return list(HOME_PATH)
    elif target.startswith("~/"):
        parts = list(HOME_PATH)
        target = target[2:]
    else:
        parts = list(cwd_parts)

    for piece in target.split("/"):
        if piece in ("", "."):
            continue
        elif piece == "..":
            if parts:
                parts.pop()
        else:
            parts.append(piece)
    return parts


def path_to_str(parts):
    if not parts:
        return "/"
    return "/" + "/".join(parts)


def display_path(parts):
    if parts[: len(HOME_PATH)] == HOME_PATH:
        rest = parts[len(HOME_PATH):]
        return "~" + ("/" + "/".join(rest) if rest else "")
    return path_to_str(parts)


def get_cwd():
    return session.get("cwd", list(HOME_PATH))


def set_cwd(parts):
    session["cwd"] = parts


def fmt_listing(node, long_form=False, show_all=False):
    if isinstance(node, str):
        return node
    names = sorted(node.keys())
    if not show_all:
        names = [n for n in names if not n.startswith(".")]
    if not long_form:
        return "  ".join(names)
    lines = []
    for name in names:
        child = node[name]
        if isinstance(child, dict):
            perms = "drwxr-xr-x"
            size = 4096
        else:
            perms = "-rw-r--r--"
            size = len(child)
        lines.append(f"{perms} 1 {USERNAME} {USERNAME} {size:>6} Jun 08 09:00 {name}")
    return "\n".join(lines)


def cmd_ls(args, cwd_parts):
    long_form = "-l" in args or "-la" in args or "-al" in args
    show_all = "-a" in args or "-la" in args or "-al" in args
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        node = get_node(cwd_parts)
        if node is None:
            return "ls: cannot access: No such file or directory", True
        return fmt_listing(node, long_form, show_all), False

    outputs = []
    err = False
    for t in targets:
        parts = normalize_path(cwd_parts, t)
        node = get_node(parts)
        if node is None:
            outputs.append(f"ls: cannot access '{t}': No such file or directory")
            err = True
        else:
            prefix = f"{t}:\n" if len(targets) > 1 else ""
            outputs.append(prefix + fmt_listing(node, long_form, show_all))
    return "\n".join(outputs), err


def cmd_cd(args, cwd_parts):
    target = args[0] if args else "~"
    new_parts = normalize_path(cwd_parts, target)
    node = get_node(new_parts)
    if node is None:
        return None, f"bash: cd: {target}: No such file or directory"
    if isinstance(node, str):
        return None, f"bash: cd: {target}: Not a directory"
    return new_parts, None


def cmd_cat(args, cwd_parts):
    if not args:
        return "cat: missing operand", True
    outputs = []
    err = False
    for t in args:
        parts = normalize_path(cwd_parts, t)
        node = get_node(parts)
        if node is None:
            outputs.append(f"cat: {t}: No such file or directory")
            err = True
        elif isinstance(node, dict):
            outputs.append(f"cat: {t}: Is a directory")
            err = True
        else:
            outputs.append(node.rstrip("\n"))
    return "\n".join(outputs), err


def cmd_grep(args, cwd_parts):
    if len(args) < 2:
        return "Usage: grep PATTERN FILE", True
    pattern = args[0]
    file_arg = args[1]
    parts = normalize_path(cwd_parts, file_arg)
    node = get_node(parts)
    if node is None:
        return f"grep: {file_arg}: No such file or directory", True
    if isinstance(node, dict):
        return f"grep: {file_arg}: Is a directory", True
    matches = [line for line in node.splitlines() if pattern in line]
    return "\n".join(matches), False


def cmd_find(args, cwd_parts):
    start = "."
    name_filter = None
    i = 0
    while i < len(args):
        if args[i] == "-name" and i + 1 < len(args):
            name_filter = args[i + 1].strip("'\"")
            i += 2
        elif not args[i].startswith("-"):
            start = args[i]
            i += 1
        else:
            i += 1

    start_parts = normalize_path(cwd_parts, start)
    node = get_node(start_parts)
    if node is None:
        return f"find: '{start}': No such file or directory", True

    results = []

    def walk(parts, n):
        rel = path_to_str(parts) if parts else "/"
        name = parts[-1] if parts else "/"
        if name_filter is None or fnmatch_simple(name, name_filter):
            results.append(rel if start != "." else "." + rel[len(path_to_str(start_parts)) :] or ".")
        if isinstance(n, dict):
            for child_name in sorted(n.keys()):
                walk(parts + [child_name], n[child_name])

    walk(start_parts, node)
    return "\n".join(results) if results else "", False


def fnmatch_simple(name, pattern):
    import fnmatch

    return fnmatch.fnmatch(name, pattern)


def cmd_head_tail(args, cwd_parts, mode):
    n = 10
    files = []
    i = 0
    while i < len(args):
        if args[i] == "-n" and i + 1 < len(args):
            try:
                n = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        else:
            files.append(args[i])
            i += 1
    if not files:
        return f"{mode}: missing operand", True
    outputs = []
    err = False
    for f in files:
        parts = normalize_path(cwd_parts, f)
        node = get_node(parts)
        if node is None:
            outputs.append(f"{mode}: cannot open '{f}' for reading: No such file or directory")
            err = True
            continue
        if isinstance(node, dict):
            outputs.append(f"{mode}: error reading '{f}': Is a directory")
            err = True
            continue
        lines = node.splitlines()
        chosen = lines[:n] if mode == "head" else lines[-n:]
        outputs.append("\n".join(chosen))
    return "\n".join(outputs), err


def cmd_wc(args, cwd_parts):
    if not args:
        return "wc: missing operand", True
    outputs = []
    err = False
    for f in args:
        parts = normalize_path(cwd_parts, f)
        node = get_node(parts)
        if node is None:
            outputs.append(f"wc: {f}: No such file or directory")
            err = True
            continue
        if isinstance(node, dict):
            outputs.append(f"wc: {f}: Is a directory")
            err = True
            continue
        lines = node.count("\n")
        words = len(node.split())
        chars = len(node)
        outputs.append(f"{lines:>7} {words:>7} {chars:>7} {f}")
    return "\n".join(outputs), err


HELP_TEXT = """Available commands:
  ls [-l -a]        list directory contents
  cd <dir>          change directory
  pwd               print working directory
  cat <file>        print file contents
  head/tail <file>  show first/last lines of a file
  grep <pat> <file> search for a pattern in a file
  find -name <pat>  search for files by name
  wc <file>         count lines/words/characters
  echo <text>       print text
  whoami            print current user
  hostname          print system hostname
  date              print current date/time
  history           show command history
  ps aux            show running processes
  netstat           show network connections
  clear             clear the terminal screen
  help              show this help message
"""


def run_command(raw, cwd_parts, history):
    raw = raw.strip()
    if not raw:
        return "", get_cwd_state(cwd_parts), False

    try:
        tokens = shlex.split(raw)
    except ValueError:
        return "bash: syntax error: unmatched quote", get_cwd_state(cwd_parts), True

    if not tokens:
        return "", get_cwd_state(cwd_parts), False

    cmd, *args = tokens
    output = ""
    err = False
    new_cwd = cwd_parts

    if cmd == "pwd":
        output = path_to_str(cwd_parts)
    elif cmd == "ls":
        output, err = cmd_ls(args, cwd_parts)
    elif cmd == "cd":
        result, error = cmd_cd(args, cwd_parts)
        if error:
            output, err = error, True
        else:
            new_cwd = result
    elif cmd == "cat":
        output, err = cmd_cat(args, cwd_parts)
    elif cmd == "grep":
        output, err = cmd_grep(args, cwd_parts)
    elif cmd == "find":
        output, err = cmd_find(args, cwd_parts)
    elif cmd in ("head", "tail"):
        output, err = cmd_head_tail(args, cwd_parts, cmd)
    elif cmd == "wc":
        output, err = cmd_wc(args, cwd_parts)
    elif cmd == "echo":
        output = " ".join(args)
    elif cmd == "whoami":
        output = USERNAME
    elif cmd == "hostname":
        output = HOSTNAME
    elif cmd == "date":
        output = datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
    elif cmd == "history":
        output = "\n".join(f"{i+1}  {h}" for i, h in enumerate(history))
    elif cmd in ("ps",):
        output = FAKE_PROCESSES
    elif cmd == "netstat":
        output = FAKE_NETSTAT
    elif cmd == "clear":
        output = "__CLEAR__"
    elif cmd == "help":
        output = HELP_TEXT
    elif cmd in ("less", "more"):
        output, err = cmd_cat(args, cwd_parts)
    else:
        output = f"bash: {cmd}: command not found"
        err = True

    return output, new_cwd, err


def get_cwd_state(parts):
    return parts


@app.route("/")
def index():
    session.setdefault("cwd", list(HOME_PATH))
    session.setdefault("history", [])
    return render_template(
        "index.html",
        username=USERNAME,
        hostname=HOSTNAME,
        prompt_path=display_path(session["cwd"]),
    )


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("command", ""))[:1000]

    cwd = session.get("cwd", list(HOME_PATH))
    history = session.get("history", [])

    output, new_cwd, err = run_command(raw, cwd, history)

    if raw.strip():
        history.append(raw.strip())
        history = history[-200:]
        session["history"] = history

    session["cwd"] = new_cwd

    return jsonify(
        {
            "output": output,
            "error": err,
            "prompt_path": display_path(new_cwd),
            "username": USERNAME,
            "hostname": HOSTNAME,
        }
    )


@app.route("/api/reset", methods=["POST"])
def api_reset():
    session["cwd"] = list(HOME_PATH)
    session["history"] = []
    return jsonify({"ok": True, "prompt_path": display_path(session["cwd"])})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
