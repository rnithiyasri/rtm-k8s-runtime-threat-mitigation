from fastapi import FastAPI, Request
import logging
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("stub-receiver")

app = FastAPI(title="stub-receiver")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "stub-receiver"}


@app.post("/alerts")
async def receive_alert(request: Request):
    body = await request.json()
    rule = body.get("rule", "unknown")
    priority = body.get("priority", "unknown")
    output = body.get("output", "")
    logger.info("ALERT rule=%s priority=%s output=%s", rule, priority, output)
    return {"received": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
