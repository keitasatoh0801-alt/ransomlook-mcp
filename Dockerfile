FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV RANSOMLOOK_API=https://www.ransomlook.io/api
ENV RANSOMLOOK_TIMEOUT=20

EXPOSE 8000

CMD ["python", "server.py"]