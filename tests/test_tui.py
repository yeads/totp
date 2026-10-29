#!/usr/bin/env python3
"""Real PTY integration tests; only the Python standard library is required."""
import errno
import codecs
import fcntl
import os
import pathlib
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unicodedata

BINARY = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./dostotp")


class Screen:
    """Track the visible ANSI screen, including updates split across PTY reads."""
    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.x = self.y = 0
        self.resize(80, 25)

    def resize(self, columns, rows):
        self.columns, self.rows = columns, rows
        self.cells = [[" "] * columns for _ in range(rows)]
        self.x = self.y = 0

    @property
    def text(self):
        return "\n".join("".join(row) for row in self.cells)

    def feed(self, chunk):
        self.pending += self.decoder.decode(chunk)
        index = 0
        while index < len(self.pending):
            c = self.pending[index]
            if c == "\x1b":
                match = re.match(r"\x1b\[([0-9;?]*)([@-~])", self.pending[index:])
                if not match:
                    break
                params, command = match.groups()
                if command == "H":
                    coords = [int(v or "1") for v in params.split(";")]
                    self.y = (coords[0] if coords else 1) - 1
                    self.x = (coords[1] if len(coords) > 1 else 1) - 1
                elif command == "J" and params == "2":
                    self.cells = [[" "] * self.columns for _ in range(self.rows)]
                index += len(match.group())
                continue
            index += 1
            if c == "\r":
                self.x = 0
            elif c == "\n":
                self.y = min(self.rows - 1, self.y + 1)
            elif ord(c) >= 32:
                if unicodedata.combining(c) or unicodedata.category(c) in ("Mn", "Me", "Cf"):
                    if 0 < self.x <= self.columns and 0 <= self.y < self.rows:
                        previous = self.x - 1
                        if not self.cells[self.y][previous] and previous:
                            previous -= 1
                        self.cells[self.y][previous] += c
                    continue
                width = 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1
                if 0 <= self.y < self.rows and 0 <= self.x < self.columns:
                    self.cells[self.y][self.x] = c
                    if width == 2 and self.x + 1 < self.columns:
                        self.cells[self.y][self.x + 1] = ""
                self.x += width
        self.pending = self.pending[index:]


class Terminal:
    def __init__(self, *args, env=None):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        self.screen = Screen()
        self.resize(80, 25)
        self.output = bytearray()
        self.mark = 0
        environment = dict(os.environ, TERM="xterm-256color", LC_ALL="C.UTF-8")
        environment.update(env or {})
        self.process = subprocess.Popen(
            [BINARY, *args], stdin=self.slave, stdout=self.slave,
            stderr=self.slave, env=environment, start_new_session=True,
        )

    def resize(self, columns, rows):
        self.screen.resize(columns, rows)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        if hasattr(self, "process"):
            self.process.send_signal(signal.SIGWINCH)

    def pump(self, seconds=0.05):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                chunk = os.read(self.master, 65536)
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            self.output.extend(chunk)
            self.screen.feed(chunk)

    def send(self, value):
        self.pump()
        self.mark = len(self.output)
        os.write(self.master, value.encode() if isinstance(value, str) else value)

    def expect(self, text, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump(0.05)
            if text in self.screen.text:
                return
        raise AssertionError(f"Missing screen text {text!r}; screen:\n{self.screen.text}")

    def finish(self, action="q", expected=0):
        if action is not None:
            self.send(action)
        deadline = time.monotonic() + 5
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump(0.05)
        assert self.process.poll() == expected, self.process.poll()
        self.pump()
        assert termios.tcgetattr(self.slave) == self.original, "Terminal attributes were not restored"
        assert b"\x1b[?1049l" in self.output, "Alternate screen was not restored"
        self.close()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        for name in ("master", "slave"):
            fd = getattr(self, name, -1)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def test_demo(root):
    with Terminal("--demo", env={"XDG_DATA_HOME": str(root / "unused")}) as t:
        t.expect("DEMONSTRATION")
        t.expect("GitHub")
        t.send("\x1bOP")
        t.expect("Help / Advise")
        t.send("\r")
        t.expect("GitHub")
        # Bracketed paste must never execute commands on the main screen.
        t.send("\x1b[200~qdal\x1b[201~")
        t.expect("DEMONSTRATION")
        assert t.process.poll() is None
        t.send("/Google\r")
        t.expect("Filter applied")
        t.send("\x1b")
        t.expect("Filter cleared")
        t.send(" ")
        t.expect("* * * * * *")
        t.resize(60, 18)
        t.expect("Resize terminal")
        t.resize(100, 32)
        t.expect("The TOTP Utilities")
        t.send("m")
        t.expect("9  Quit")
        t.finish("9")
    assert not (root / "unused").exists(), "Demo created persistent data"


def test_vault(root):
    path = root / "test.vault"
    password = "test-master-passphrase"
    replacement = "changed-master-passphrase"
    uri = "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    with Terminal("--vault", str(path)) as t:
        t.expect("Create encrypted vault")
        t.send(password + "\t" + password + "\r")
        t.expect("Vault created")
        assert path.exists()
        t.send("i")
        t.expect("Import TOTP account")
        t.send("\x1b[200~" + uri + "\x1b[201~\r")
        t.expect("Changes saved")
        t.expect("alice@example.com")
        assert b"JBSWY3DPEHPK3PXP" not in t.output, "Secret was echoed during import"
        t.send("e")
        t.expect("Edit account")
        t.send("\t\x15renamed@example.com\r")
        t.expect("Changes saved")
        t.expect("renamed@example.com")
        t.send("/nomatch\r")
        t.expect("No matches")
        t.send("\x1b")
        t.expect("Filter cleared")
        t.send("a")
        t.expect("Add account")
        t.send("Manual\tsecond@example.com\tJBSWY3DPEHPK3PXP\r")
        t.expect("Changes saved")
        t.expect("002 accounts")
        t.send("d")
        t.expect("Delete account")
        t.send("n")
        t.expect("002 accounts")
        t.send("d")
        t.expect("Delete account")
        t.send("y")
        t.expect("001 accounts")
        t.send("s")
        t.expect("Configuration")
        t.send("1")
        t.expect("Change master password")
        t.send(password + "\t" + replacement + "\t" + replacement + "\r")
        t.expect("Master password changed")
        t.send("l")
        t.expect("Unlock vault")
        t.send(password + "\r")
        t.expect("Wrong password")
        t.send("\r")
        t.expect("Unlock vault")
        t.send(replacement + "\r")
        t.expect("Vault unlocked. Changes")
        assert password.encode() not in t.output and replacement.encode() not in t.output
        t.finish()
    assert path.stat().st_mode & 0o777 == 0o600
    assert b"JBSWY3DPEHPK3PXP" not in path.read_bytes()
    with Terminal("--vault", str(path), "--timeout", "1") as t:
        t.expect("Unlock vault")
        t.send(replacement + "\r")
        t.expect("Vault unlocked. Changes")
        t.expect("renamed@example.com")
        t.send("a")
        t.expect("Add account")
        t.mark = len(t.output)
        t.expect("Vault locked after inactivity", timeout=4)
        t.expect("Unlock vault")
        t.finish("\x1b")


def test_default_path(root):
    data = root / "data"
    with Terminal(env={"XDG_DATA_HOME": str(data)}) as t:
        t.expect("Create encrypted vault")
        t.send("default-password\tdefault-password\r")
        t.expect("Vault created")
        t.finish()
    assert (data / "dostotp/accounts.vault").exists()
    assert (data / "dostotp").stat().st_mode & 0o777 == 0o700


def test_signal():
    with Terminal("--demo", "--ansi") as t:
        t.expect("DEMONSTRATION")
        t.process.send_signal(signal.SIGTERM)
        t.finish(None, 128 + signal.SIGTERM)


def test_incremental_rendering():
    for palette in ((), ("--ansi",)):
        with Terminal("--demo", *palette) as t:
            t.expect("DEMONSTRATION")
            t.pump(0.3)
            start = len(t.output)
            t.pump(2.2)
            updates = bytes(t.output[start:])
            assert updates, "The countdown stopped updating"
            assert len(updates) < 2048, f"Idle redraw sent {len(updates)} bytes"
            rows = {int(row) for row in re.findall(rb"\x1b\[(\d+);\d+H", updates)}
            assert rows <= {11, 13, 14}, f"Unchanged rows were repainted: {rows}"
            assert b"\x1b[2J" not in updates, "Idle refresh cleared the screen"
            t.send("h")
            t.expect("Help / Advise")
            t.pump(0.3)
            start = len(t.output)
            t.pump(1.2)
            assert len(t.output) == start, "An unchanged dialog still repaints"
            t.send("\r")
            t.expect("GitHub")
            t.send("\x1b[B")
            t.expect("alex@example.com")
            t.send("s")
            t.expect("1  Change master password")
            start = len(t.output)
            t.send("4")
            t.expect("alex@example.com")
            assert len(t.output) - start > 2000, "Palette change did not repaint the screen"
            t.finish()


def test_unicode_rendering():
    with Terminal("--demo") as t:
        t.expect("DEMONSTRATION")
        t.send("a")
        t.expect("Add account")
        t.send("\x1b[200~邮件\x1b[201~\t\x1b[200~账户e\u0301\x1b[201~\tJBSWY3DPEHPK3PXP\r")
        t.expect("Demo updated in memory")
        t.expect("邮件")
        t.expect("账户e\u0301")
        t.send("e")
        t.expect("Edit account")
        t.send("\x15Mail\t\x15x\r")
        t.expect("Demo updated in memory")
        assert "邮件" not in t.screen.text and "账户" not in t.screen.text, "Wide glyphs left stale cells"
        t.send("h")
        t.expect("Help / Advise")
        for columns, rows in ((76, 24), (120, 40), (240, 80), (40, 12), (80, 25)):
            t.resize(columns, rows)
            t.expect("Resize terminal" if columns < 76 else "Help / Advise")
        t.send("\r")
        t.expect("Mail / x")
        t.finish()


def main():
    subprocess.run([BINARY, "--help"], check=True, stdout=subprocess.DEVNULL)
    result = subprocess.run([BINARY, "--timeout", "invalid"], capture_output=True)
    assert result.returncode == 2
    result = subprocess.run([BINARY, "--demo"], capture_output=True)
    assert result.returncode == 1 and b"interactive terminal" in result.stderr
    with tempfile.TemporaryDirectory(prefix="dostotp-pty-") as directory:
        root = pathlib.Path(directory)
        test_demo(root)
        test_vault(root)
        test_default_path(root)
    test_signal()
    test_incremental_rendering()
    test_unicode_rendering()
    print("PASS: PTY workflows, incremental refresh, idle dialogs, palettes, Unicode, resize and terminal restoration.")


if __name__ == "__main__":
    main()
