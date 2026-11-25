FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

WORKDIR /app

COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ksc2pan /app/ksc2pan

RUN useradd -r -u 10001 -s /usr/sbin/nologin ksc2pan \
    && mkdir -p /data/edl /etc/ksc2pan \
    && chown -R 10001:10001 /data /etc/ksc2pan
USER 10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3).status==200 else 1)"

CMD ["uvicorn", "ksc2pan.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
