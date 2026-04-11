import asyncio
import json
from typing import Any

from fastapi import APIRouter, Query, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.api.dashboard import compute_dashboard_summary
from app.core.security import decode_token
from app.db import SessionLocal
from app.models import User

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = decode_token(token)
    except ValueError:
        await websocket.close(code=4401)
        return
    uid = payload.get("uid")
    if not isinstance(uid, int):
        await websocket.close(code=4401)
        return

    await websocket.accept()

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
