from __future__ import annotations

import asyncio
import re
import struct
from dataclasses import dataclass, field


class TelnetTransportError(RuntimeError):
    pass


IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

OPT_ECHO = 1
OPT_SUPPRESS_GO_AHEAD = 3
OPT_TERMINAL_TYPE = 24
OPT_NAWS = 31
TTYPE_IS = 0
TTYPE_SEND = 1

_LOGIN_PROMPT = re.compile(rb"(?:login|username|user\s+name)\s*[:>]\s*$", re.IGNORECASE)
_PASSWORD_PROMPT = re.compile(rb"password\s*[:>]\s*$", re.IGNORECASE)
_LOGIN_FAILURE = re.compile(
    rb"(?:login\s+incorrect|authentication\s+failed|access\s+denied|invalid\s+password|login\s+failed)",
    re.IGNORECASE,
)


@dataclass
class TelnetCodec:
    """Minimal RFC-854 negotiation codec for an interactive network terminal.

    The codec strips Telnet control traffic from terminal output and emits only
    conservative option responses. Credentials are never inspected here.
    """

    rows: int = 30
    cols: int = 120
    terminal_type: str = "xterm-256color"
    pending: bytearray = field(default_factory=bytearray, repr=False)

    def _naws(self) -> bytes:
        rows = max(5, min(int(self.rows), 300))
        cols = max(20, min(int(self.cols), 500))
        payload = struct.pack("!HH", cols, rows).replace(bytes([IAC]), bytes([IAC, IAC]))
        return bytes([IAC, SB, OPT_NAWS]) + payload + bytes([IAC, SE])

    def resize(self, rows: int, cols: int) -> bytes:
        self.rows = max(5, min(int(rows), 300))
        self.cols = max(20, min(int(cols), 500))
        return self._naws()

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        if data:
            self.pending.extend(data)
        visible = bytearray()
        reply = bytearray()
        index = 0
        raw = self.pending

        while index < len(raw):
            value = raw[index]
            if value != IAC:
                visible.append(value)
                index += 1
                continue
            if index + 1 >= len(raw):
                break
            command = raw[index + 1]
            if command == IAC:
                visible.append(IAC)
                index += 2
                continue
            if command in {DO, DONT, WILL, WONT}:
                if index + 2 >= len(raw):
                    break
                option = raw[index + 2]
                if command == DO:
                    if option in {OPT_SUPPRESS_GO_AHEAD, OPT_TERMINAL_TYPE, OPT_NAWS}:
                        reply.extend((IAC, WILL, option))
                        if option == OPT_NAWS:
                            reply.extend(self._naws())
                    else:
                        reply.extend((IAC, WONT, option))
                elif command == WILL:
                    if option in {OPT_ECHO, OPT_SUPPRESS_GO_AHEAD}:
                        reply.extend((IAC, DO, option))
                    else:
                        reply.extend((IAC, DONT, option))
                index += 3
                continue
            if command == SB:
                end = index + 2
                while end + 1 < len(raw):
                    if raw[end] == IAC and raw[end + 1] == SE:
                        break
                    end += 1
                if end + 1 >= len(raw):
                    break
                payload = bytes(raw[index + 2:end])
                if (
                    len(payload) >= 2
                    and payload[0] == OPT_TERMINAL_TYPE
                    and payload[1] == TTYPE_SEND
                ):
                    terminal = self.terminal_type.encode("ascii", "ignore")[:64]
                    terminal = terminal.replace(bytes([IAC]), bytes([IAC, IAC]))
                    reply.extend(
                        bytes([IAC, SB, OPT_TERMINAL_TYPE, TTYPE_IS])
                        + terminal
                        + bytes([IAC, SE])
                    )
                index = end + 2
                continue
            # Single-byte Telnet commands (NOP, GA, etc.) are consumed.
            index += 2

        if index:
            del raw[:index]
        return bytes(visible), bytes(reply)


@dataclass
class TelnetConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    codec: TelnetCodec
    initial_output: bytes = field(default=b"", repr=False)
    closed: bool = False

    async def read(self, size: int = 4096) -> bytes:
        while not self.closed:
            chunk = await self.reader.read(size)
            if not chunk:
                self.closed = True
                return b""
            visible, reply = self.codec.feed(chunk)
            if reply:
                self.writer.write(reply)
                await self.writer.drain()
            if visible:
                return visible
        return b""

    async def write(self, data: bytes) -> None:
        if self.closed or not data:
            return
        escaped = data.replace(bytes([IAC]), bytes([IAC, IAC]))
        self.writer.write(escaped)
        await self.writer.drain()

    async def resize(self, rows: int, cols: int) -> None:
        if self.closed:
            return
        self.writer.write(self.codec.resize(rows, cols))
        await self.writer.drain()

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


async def _read_until_prompt(
    connection: TelnetConnection,
    pattern: re.Pattern[bytes],
    *,
    timeout_seconds: float,
    limit: int = 32768,
) -> bytes:
    buffer = bytearray()
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while len(buffer) < limit:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TelnetTransportError("TELNET_LOGIN_PROMPT_TIMEOUT")
        try:
            chunk = await asyncio.wait_for(connection.read(4096), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise TelnetTransportError("TELNET_LOGIN_PROMPT_TIMEOUT") from exc
        if not chunk:
            raise TelnetTransportError("TELNET_CONNECTION_CLOSED")
        buffer.extend(chunk)
        if _LOGIN_FAILURE.search(buffer):
            raise TelnetTransportError("TELNET_LOGIN_FAILED")
        tail = bytes(buffer[-4096:])
        if pattern.search(tail):
            return bytes(buffer)
    raise TelnetTransportError("TELNET_LOGIN_PROMPT_TOO_LARGE")


async def start_telnet(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    timeout_seconds: int = 10,
    rows: int = 30,
    cols: int = 120,
) -> TelnetConnection:
    """Open and authenticate one legacy Telnet session.

    Telnet is plaintext transport by design. Callers must enforce the global
    disabled-by-default policy before reaching this function.
    """

    if not username or not password:
        raise TelnetTransportError("TELNET_CREDENTIALS_REQUIRED")
    try:
        timeout = max(1, min(int(timeout_seconds), 60))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=int(port)),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        raise TelnetTransportError("TELNET_CONNECTION_FAILED") from exc

    connection = TelnetConnection(
        reader=reader,
        writer=writer,
        codec=TelnetCodec(rows=rows, cols=cols),
    )
    try:
        login_output = await _read_until_prompt(
            connection,
            _LOGIN_PROMPT,
            timeout_seconds=float(timeout),
        )
        await connection.write(username.encode("utf-8", "replace") + b"\r\n")
        password_output = await _read_until_prompt(
            connection,
            _PASSWORD_PROMPT,
            timeout_seconds=float(timeout),
        )
        await connection.write(password.encode("utf-8", "replace") + b"\r\n")

        # Give the device a short bounded window to reject bad credentials.
        # Successful vendor shells need not expose a standardized prompt.
        post_auth = b""
        try:
            post_auth = await asyncio.wait_for(connection.read(4096), timeout=1.5)
        except asyncio.TimeoutError:
            pass
        if _LOGIN_FAILURE.search(post_auth):
            raise TelnetTransportError("TELNET_LOGIN_FAILED")
        connection.initial_output = login_output + password_output + post_auth
        return connection
    except Exception:
        await connection.close()
        raise
