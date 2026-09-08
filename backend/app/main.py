"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

app = FastAPI(
    title="Network Attack Path Analyzer",
    version="0.7.0",
    description="Defensive network security assessment API with attack-path analysis, explainable risk scoring, what-if simulation, reporting, and AI-assisted explanation. Developed by MD Jubayer Khan Akash.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
