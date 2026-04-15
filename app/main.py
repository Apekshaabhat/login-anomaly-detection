from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, admin, simulation
from app.database.connection import engine
from app.database.models import Base

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Universal Login Security Middleware API",
    description="A production-grade API for login security, anomaly detection, and behavioral analysis",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin.router, prefix="/api/admin", tags=["Administration"])
app.include_router(simulation.router, prefix="/api/simulation", tags=["Simulation"])

@app.get("/")
def read_root():
    return {"message": "Universal Login Security Middleware API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}