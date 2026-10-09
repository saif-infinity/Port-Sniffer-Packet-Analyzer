import asyncio

from psa.scanner import clean_banner, scan_host


def test_clean_banner_strips_control_characters():
    assert clean_banner(b"SSH-2.0-OpenSSH_9.6\r\n") == "SSH-2.0-OpenSSH_9.6"
    assert clean_banner(b"\x00\x01bad\x1b[31m") == "bad [31m"
    assert clean_banner(b"a\r\n\r\nb") == "a b"
    assert clean_banner(b"") is None


def test_scan_detects_open_closed_and_banner():
    async def run():
        async def handler(reader, writer):
            writer.write(b"HELLO-BANNER\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        open_port = server.sockets[0].getsockname()[1]
        # Find a port that is certainly closed: bind then release it.
        probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        closed_port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()

        try:
            results = await scan_host("127.0.0.1", [open_port, closed_port], timeout=2, grab_banner=True)
        finally:
            server.close()
            await server.wait_closed()
        return open_port, closed_port, {r.port: r for r in results}

    open_port, closed_port, by_port = asyncio.run(run())
    assert by_port[open_port].state == "open"
    assert by_port[open_port].banner == "HELLO-BANNER"
    assert by_port[open_port].latency_ms is not None
    assert by_port[closed_port].state == "closed"


def test_http_like_port_gets_head_probe():
    async def run():
        async def handler(reader, writer):
            await reader.readuntil(b"\r\n\r\n")  # wait for the HEAD request
            writer.write(b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            # Port 8000 is in HTTP_LIKE_PORTS; the probe is keyed on the port number,
            # so monkeypatch the set for this test by using the real logic on our port.
            from psa import scanner
            scanner.HTTP_LIKE_PORTS.add(port)
            try:
                results = await scan_host("127.0.0.1", [port], timeout=2, grab_banner=True)
            finally:
                scanner.HTTP_LIKE_PORTS.discard(port)
        finally:
            server.close()
            await server.wait_closed()
        return results[0]

    result = asyncio.run(run())
    assert result.state == "open"
    assert result.banner == "HTTP/1.0 200 OK Server: test"
