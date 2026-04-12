import asyncio
import json
from typing import Any

from fastapi import APIRouter
from starlette.websockets import WebSocket, WebSocketDisconnect

from app.api.dashboard import compute_dashboard_summary
from app.core.security import decode_token
from app.db import SessionLocal
from app.models import User

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    """WebSocket endpoint for live dashboard updates.

    Authentication is performed via the first message received after connection,
    which must be: {"type": "auth", "token": "<JWT>"}
    This avoids exposing the token in the URL (proxy logs, browser history).
    """
    await websocket.accept()

    # Step 1 — wait for auth message (5-second timeout)
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        msg = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        await websocket.close(code=4401)
        return

    if msg.get("type") != "auth" or not msg.get("token"):
        await websocket.close(code=4401)
        return

    # Step 2 — validate token
    try:
        payload = decode_token(msg["token"])
    except ValueError:
        await websocket.close(code=4401)
        return

    uid = payload.get("uid")
    if not isinstance(uid, int):
        await websocket.close(code=4401)
        return

    # Step 3 — push loop
    try:
        while True:
            db = SessionLocal()
            try:
                user = db.get(User, uid)
                if user is None:
                    await websocket.close(code=4401)
                    return
                payload_out: dict[str, Any] = await asyncio.to_thread(compute_dashboard_summary, db, user)
            finally:
                db.close()
            await websocket.send_json({"type": "dashboard", "payload": payload_out})
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": "internal"}))
        except Exception:
            pass
        await websocket.close(code=1011)
