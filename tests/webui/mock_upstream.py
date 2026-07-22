"""Mock LLM upstream for secret-guard UI regression tests.

Zero-dependency (stdlib only) mock that pretends to be an OpenAI-compatible
endpoint. Supports both non-streaming and streaming (SSE) responses.

Started as a child process by Playwright's `webServer` config. Prints a
ready line on stderr so Playwright knows when it's listening.

Usage:
    MOCK_PORT=19999 python3 tests/webui/mock_upstream.py
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORT = 19999
STREAM_CHUNK_DELAY = 0.3  # seconds between SSE chunks


def _build_reply(user_msg: str) -> str:
    """Build a reply of appropriate length based on the user message."""
    if "long response" in user_msg.lower():
        return "This is a long response for testing the typing box. " * 20
    return "Hello! This is a mock response."


def _handle_non_stream(req_body: dict) -> bytes:
    """Build a non-streaming OpenAI Chat Completions response."""
    user_msg = ""
    for m in req_body.get("messages", []):
        if m.get("role") == "user":
            content = m.get("content", "")
            if isinstance(content, str):
                user_msg = content
            elif isinstance(content, list):
                user_msg = " ".join(
                    b.get("text", "") for b in content if b.get("type") == "text"
                )
            break

    reply = _build_reply(user_msg)
    return json.dumps(
        {
            "choices": [
                {
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                    "index": 0,
                }
            ],
            "model": req_body.get("model", "test-model"),
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }
    ).encode()


def _handle_stream(wfile) -> None:
    """Emit SSE chunks slowly, simulating a streaming response."""
    words = ["Hello", "world", "this", "is", "streaming", "response", "for", "testing"]
    for word in words:
        chunk = {
            "choices": [
                {"delta": {"content": word + " "}, "finish_reason": None, "index": 0}
            ]
        }
        wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
        wfile.flush()
        time.sleep(STREAM_CHUNK_DELAY)
    terminator = {"choices": [{"delta": {}, "finish_reason": "stop", "index": 0}]}
    wfile.write(f"data: {json.dumps(terminator)}\n\n".encode())
    wfile.flush()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req_body = json.loads(raw)
        except json.JSONDecodeError:
            req_body = {}

        if req_body.get("stream") is True:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            _handle_stream(self.wfile)
        else:
            body = _handle_non_stream(req_body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass  # silent


def main() -> None:
    port = int(os.environ.get("MOCK_PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock upstream listening on 127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
