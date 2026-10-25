from app.configuration.contracts import ConfigurationTransport
from app.remote_gateway.telnet_transport import (
    DO,
    IAC,
    OPT_NAWS,
    OPT_TERMINAL_TYPE,
    SB,
    SE,
    TTYPE_SEND,
    WILL,
    TelnetCodec,
)


def test_telnet_configuration_transport_is_explicit():
    assert ConfigurationTransport("TELNET_CLI") is ConfigurationTransport.TELNET_CLI


def test_telnet_codec_negotiates_naws_without_exposing_control_bytes():
    codec = TelnetCodec(rows=40, cols=132)
    visible, reply = codec.feed(bytes([IAC, DO, OPT_NAWS]))
    assert visible == b""
    assert reply.startswith(bytes([IAC, WILL, OPT_NAWS]))
    assert bytes([IAC, SB, OPT_NAWS]) in reply
    assert reply.endswith(bytes([IAC, SE]))


def test_telnet_codec_replies_to_terminal_type_request():
    codec = TelnetCodec(terminal_type="xterm-256color")
    packet = bytes([IAC, SB, OPT_TERMINAL_TYPE, TTYPE_SEND, IAC, SE])
    visible, reply = codec.feed(packet)
    assert visible == b""
    assert b"xterm-256color" in reply
    assert reply.startswith(bytes([IAC, SB, OPT_TERMINAL_TYPE]))


def test_telnet_codec_preserves_terminal_data_and_escaped_iac():
    codec = TelnetCodec()
    visible, reply = codec.feed(b"router> " + bytes([IAC, IAC]) + b"\r\n")
    assert visible == b"router> " + bytes([IAC]) + b"\r\n"
    assert reply == b""


def test_telnet_codec_handles_split_negotiation_packet():
    codec = TelnetCodec()
    visible, reply = codec.feed(bytes([IAC, DO]))
    assert visible == b""
    assert reply == b""
    visible, reply = codec.feed(bytes([OPT_NAWS]) + b"ready")
    assert visible == b"ready"
    assert reply.startswith(bytes([IAC, WILL, OPT_NAWS]))
