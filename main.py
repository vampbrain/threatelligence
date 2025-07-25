from fastapi import FastAPI
from api.endpoints import router as api_router

app = FastAPI(
    title="Threat Intelligence Aggregator API",
    description="Aggregates, extracts, enriches, and summarizes cyber threat intelligence.",
    version="1.0.0"
)

app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
