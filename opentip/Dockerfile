# OpenTIP — Open Threat Intelligence Platform
# Çok aşamalı olmayan, sade ve tekrarlanabilir bir imaj.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_ENABLE_CORS=false

WORKDIR /app

# Önce yalnızca bağımlılıklar kopyalanır; kod değiştiğinde katman önbelleği korunur.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodu (.env ve veri dizinleri .dockerignore ile hariç tutulur).
COPY . .

# Arayüz ve testler root olmayan kullanıcıyla çalışır.
RUN useradd --create-home --uid 10001 opentip \
    && mkdir -p /app/data /app/reports_output \
    && chown -R opentip:opentip /app
USER opentip

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys,urllib.request;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health').status==200 else 1)"

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
