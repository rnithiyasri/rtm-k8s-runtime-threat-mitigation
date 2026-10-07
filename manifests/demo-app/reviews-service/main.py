from fastapi import FastAPI
import uvicorn

app = FastAPI(title="reviews-service")

@app.get("/health")
def health():
    return {"status": "ok", "service": "reviews-service"}

@app.get("/reviews")
def reviews():
    return {'reviews': [{'id': 1, 'text': 'Great product!', 'rating': 5}]}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
