from fastapi import FastAPI
import uvicorn

app = FastAPI(title="frontend")

@app.get("/health")
def health():
    return {"status": "ok", "service": "frontend"}

@app.get("/store")
def store():
    return {'items': ['widget', 'gadget', 'doohickey']}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
