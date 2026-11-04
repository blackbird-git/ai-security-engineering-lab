"""Static diagnostics only; no model, data, or tool access."""

from fastapi import FastAPI


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Report application liveness without contacting other services."""
    return {"status": "ok"}
