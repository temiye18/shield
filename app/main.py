from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api import auth, detection, analytics

app = FastAPI(
    title="AI Data Privacy Shield",
    description="Real-time AI data privacy platform — detect and redact PII from AI prompts",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/v1/auth", tags=["Authentication"])
app.include_router(detection.router, prefix="/v1/detect", tags=["Detection"])
app.include_router(analytics.router, prefix="/v1/analytics", tags=["Analytics"])


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}
