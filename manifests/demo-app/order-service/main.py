from fastapi import FastAPI
import uvicorn

app = FastAPI(title="order-service")

@app.get("/health")
def health():
    return {"status": "ok", "service": "order-service"}

@app.get("/orders")
def orders():
    return {'orders': [{'id': 1, 'item': 'widget', 'status': 'pending'}]}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
