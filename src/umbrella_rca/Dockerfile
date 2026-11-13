FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/umbrella_rca

ENV PYTHONPATH=/app
ENV UMBRELLA_RCA_PORT=8085

EXPOSE 8085

CMD ["uvicorn", "umbrella_rca.server:app", "--host", "0.0.0.0", "--port", "8085"]
