FROM python:3.11-slim

# Create non-root user but keep /bin/sh available
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

USER appuser
EXPOSE 8004
CMD ["python", "main.py"]
