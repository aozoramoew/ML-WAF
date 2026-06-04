FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the API port (hint only — actual port comes from $PORT at runtime)
EXPOSE 8000

# Set production environment variables
ENV ENVIRONMENT=production \
    PORT=8000

# Shell form so $PORT is expanded at container runtime.
# Hosting platforms (Railway, Render, Fly.io, etc.) inject PORT automatically.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
