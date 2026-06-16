FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=120 --retries 10 -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the API port (hint only — actual port comes from $PORT at runtime)
EXPOSE 8000

# Set production environment variables
ENV ENVIRONMENT=production \
    PORT=8000

# Train model on first boot if waf_model.pkl is absent (not committed to git).
# On subsequent restarts the existing pkl is reused — training is skipped.
CMD ["sh", "-c", "[ -f models/waf_model.pkl ] || python -m ml.train && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
