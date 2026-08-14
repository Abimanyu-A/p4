# Sandbox image for P4's own verify stage — see vuln_flask_api/Dockerfile
# for the rationale. Runs worker.py unmodified.
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.py ./

EXPOSE 5001
CMD ["flask", "--app", "worker", "run", "--host=0.0.0.0", "--port=5001"]
