from fastapi import FastAPI
import uvicorn

app = FastAPI(title="TaxBox API - Working Version")

@app.get("/")
def read_root():
    return {"message": "TaxBox API is running successfully!", "version": "1.0"}

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "TaxBox API"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
