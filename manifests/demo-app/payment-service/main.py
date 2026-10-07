from fastapi import FastAPI
import uvicorn

app = FastAPI(title="payment-service")

@app.get("/health")
def health():
    return {"status": "ok", "service": "payment-service"}

@app.get("/payments")
def payments():
    return {'status': 'ok', 'balance': 100.00}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8004)
