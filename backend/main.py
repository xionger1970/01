from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import routes

app = FastAPI(
    title="网络攻击态势感知系统",
    description="实时监控和分析网络攻击的态势感知系统",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, set specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(routes.router, prefix="/api")

@app.get("/")
def read_root():
    return {"message": "网络攻击态势感知系统 API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.on_event("startup")
def startup_event():
    from app.simulation.data_simulator import data_simulator
    data_simulator.start()

@app.on_event("shutdown")
def shutdown_event():
    from app.simulation.data_simulator import data_simulator
    data_simulator.stop()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
