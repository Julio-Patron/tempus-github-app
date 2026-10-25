"""FastAPI Webhook Server for receiving and verifying GitHub App events."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from .webhook import (
    GitHubWebhookHandler,
    WebhookVerificationError,
    verify_webhook_signature,
)

try:
    from fastapi import FastAPI, Header, HTTPException, Request, Response
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


def create_webhook_app(
    webhook_secret: str | None = None,
    handler: GitHubWebhookHandler | None = None,
) -> FastAPI:
    """Create a configured FastAPI application for GitHub webhooks."""
    if FastAPI is None:
        raise ImportError(
            "FastAPI is required for the webhook server. Run: pip install tempus-github-app[server]"
        )

    secret = webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    event_handler = handler or GitHubWebhookHandler(secret)

    app = FastAPI(
        title="Tempus GitHub App Webhook Server",
        description="Receives, verifies, and dispatches GitHub App events for Tempus DDB",
        version="0.1.0",
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "tempus-github-app-server"}

    @app.post("/webhook")
    async def receive_webhook(
        request: Request,
        x_github_event: str | None = Header(None, alias="X-GitHub-Event"),
        x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
        x_github_delivery: str | None = Header(None, alias="X-GitHub-Delivery"),
    ) -> Response:
        if not secret:
            raise HTTPException(
                status_code=500,
                detail="Server misconfigured: GITHUB_WEBHOOK_SECRET is not set",
            )

        payload_bytes = await request.body()

        # Strict signature check
        if not verify_webhook_signature(payload_bytes, secret, x_hub_signature_256):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing X-Hub-Signature-256 signature",
            )

        event_name = x_github_event or "unknown"

        # GitHub ping event sent during app webhook setup
        if event_name == "ping":
            try:
                event_handler.accept_delivery(x_github_delivery)
            except WebhookVerificationError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc
            return JSONResponse({"status": "pong", "zen": "Responsive to webhooks"})

        try:
            result = event_handler.handle(
                event_name=event_name,
                payload_bytes=payload_bytes,
                signature_header=x_hub_signature_256,
                delivery_id=x_github_delivery,
            )
            return JSONResponse(
                {
                    "status": "accepted",
                    "event": event_name,
                    "handled": result is not None,
                    "result": result,
                }
            )
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed JSON payload: {exc}",
            ) from exc
        except WebhookVerificationError as exc:
            raise HTTPException(
                status_code=401,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            logger.exception("Unhandled error processing %s webhook", event_name)
            raise HTTPException(
                status_code=500,
                detail="Error handling event",
            ) from exc

    return app


def main(argv: list[str] | None = None) -> None:
    try:
        import uvicorn
    except ImportError:
        print(
            "Error: Uvicorn is required to run the server. Run: pip install tempus-github-app[server]",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    parser = argparse.ArgumentParser(
        prog="tempus-github-app-server",
        description="Run the Tempus GitHub App webhook receiver server",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("GITHUB_WEBHOOK_HOST", "0.0.0.0"),
        help="Host to bind server (default: 0.0.0.0, env: GITHUB_WEBHOOK_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("GITHUB_WEBHOOK_PORT", "8000")),
        help="Port to bind server (default: 8000, env: GITHUB_WEBHOOK_PORT)",
    )
    parser.add_argument(
        "--secret",
        default=os.environ.get("GITHUB_WEBHOOK_SECRET"),
        help="GitHub webhook HMAC secret (env: GITHUB_WEBHOOK_SECRET)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development",
    )

    args = parser.parse_args(argv)

    if not args.secret:
        print(
            "Error: Webhook secret is required via --secret or GITHUB_WEBHOOK_SECRET",
            file=sys.stderr,
        )
        raise SystemExit(1)

    app = create_webhook_app(webhook_secret=args.secret)
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
