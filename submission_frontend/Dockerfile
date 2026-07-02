FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY main.py .

# Expose port
EXPOSE 8080

# Run FastAPI app
CMD ["python", "main.py"]
