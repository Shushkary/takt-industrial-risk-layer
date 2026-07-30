# Синтетический стенд TAKT — лёгкий API-сервер с демо-данными.
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY synthetic_data.py benchmark.py server.py ./

EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8090/health', timeout=3)"

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8090"]
