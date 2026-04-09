from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import routes
# Initialize database
from app.core import db_initializer

app = FastAPI(
    title="Web Attack Situational Awareness System",
    description="A system for real-time monitoring and analysis of web attacks",
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
    return {"message": "Web Attack Situational Awareness System API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
