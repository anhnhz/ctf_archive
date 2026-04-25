FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /deps /usr/local/lib/python3.12/site-packages/
COPY app/ ./app/
EXPOSE 5000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
