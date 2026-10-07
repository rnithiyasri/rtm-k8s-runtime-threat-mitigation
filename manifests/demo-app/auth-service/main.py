from fastapi import FastAPI
import uvicorn

app = FastAPI(title="auth-service")

@app.get("/health")
def health():
    return {"status": "ok", "service": "auth-service"}

@app.get("/login")
def login():
    return {'token': 'demo-token-abc123', 'user': 'demo'}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
