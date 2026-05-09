FROM python:3.13.3-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libmagic1 \
    chromium \
    chromium-driver \
    libjpeg-dev \
    libpng-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libopenjp2-7-dev \
    libtiff5-dev \
    libwebp-dev \
    zlib1g-dev \
    build-essential \
    wget \
    curl \
    unzip \
    sudo \
    e2fsprogs \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt* ./
RUN pip install --no-cache-dir \
    flask \
    selenium \
    pillow \
    python-magic \
    werkzeug \
    bleach \
    && if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

COPY package.json* ./
RUN if [ -f package.json ]; then \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && npm install \
    && rm -rf /var/lib/apt/lists/*; \
    fi

COPY . .

RUN chmod +x /app/cleanup_daemon.sh

RUN chmod +x /app/entrypoint.sh

RUN mkdir -p upload report static assets templates \
    && mkdir -p upload/quarantine upload/temp

ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app
ENV FLAG=SECRET

EXPOSE 5000

RUN groupadd -r nonroot && useradd -r -g nonroot nonroot \
    && groupadd -r appuser && useradd -r -g appuser appuser \
    && chown -R nonroot:nonroot /app \
    && chmod 755 /app \
    && mkdir -p /app/upload /app/notes /app/upload/quarantine /app/upload/temp \
    && chmod 755 /app/upload /app/notes /app/upload/quarantine /app/upload/temp \
    && chown -R nonroot:nonroot /app/upload /app/notes

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:5000/ || exit 1

CMD ["/app/entrypoint.sh"]
