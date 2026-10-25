"""Deterministic mock vendor GUI for Phase-E Web-GUI proxy qualification.

Run over HTTP with uvicorn, or over HTTPS using the companion test Dockerfile.
The app intentionally exercises redirects, cookies, root/absolute assets,
POST forms, dynamic fetches and WebSocket echo behavior.
"""
from __future__ import annotations

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/")
async def index(request: Request):
    absolute = str(request.base_url).rstrip("/")
    return HTMLResponse(f'''<!doctype html><html><head>
<link rel="stylesheet" href="/asset.css"><link rel="stylesheet" href="/referer-required.css"><script src="/script.js"></script></head><body>
<h1>FTTW mock device GUI</h1><img src="{absolute}/image.svg">
<a id="redirect" href="/redirect">redirect</a>
<form method="post" action="/form"><input name="value" value="ok"><button>submit</button></form>
<div id="dynamic"></div><script>fetch('/api/state').then(r=>r.json()).then(v=>dynamic.textContent=v.state);</script>
</body></html>''')


@app.get("/redirect")
async def redirect():
    return RedirectResponse("/cookie", status_code=302)


@app.get("/external-redirect")
async def external_redirect():
    return RedirectResponse("https://example.invalid/escape", status_code=302)


@app.get("/cookie")
async def cookie():
    response = HTMLResponse("cookie set")
    response.set_cookie("vendor_session", "mock-session", httponly=True, samesite="strict")
    return response


@app.get("/cookie-check")
async def cookie_check(request: Request):
    return JSONResponse({"vendor_cookie_present": request.cookies.get("vendor_session") == "mock-session"})


@app.post("/form")
async def form(request: Request):
    body = await request.body()
    return JSONResponse({"received": bool(body), "content_type": request.headers.get("content-type")})


@app.get("/api/state")
async def state():
    return {"state": "ready"}


@app.get("/asset.css")
async def css():
    return Response("body{background-image:url('/image.svg')}", media_type="text/css")


@app.get("/script.js")
async def script():
    return Response("window.mockSocketPath='/ws';", media_type="application/javascript")


@app.get("/image.svg")
async def image():
    return Response('<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><rect width="20" height="20"/></svg>', media_type="image/svg+xml")


@app.websocket("/ws")
async def websocket_echo(websocket: WebSocket):
    await websocket.accept()
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        if message.get("text") is not None:
            await websocket.send_text(message["text"])
        elif message.get("bytes") is not None:
            await websocket.send_bytes(message["bytes"])


@app.get("/referer-required.css")
async def referer_required_css(request: Request):
    expected = str(request.base_url).rstrip("/") + "/"
    referer = request.headers.get("referer", "")
    if not referer.startswith(expected):
        return Response("referer required", status_code=403, media_type="text/plain")
    return Response(".referer-ok{display:block}", media_type="text/css")
