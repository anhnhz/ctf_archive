FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && apt-get install -y     chromium     chromium-driver     && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY config.json .
COPY templates ./templates


ENV PYPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

EXPOSE 5000

CMD ["python3", "app.py"]