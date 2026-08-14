# Sandbox image for P4's own verify stage — builds and runs the vulnerable
# app unmodified (see app.py) so a confirmed finding can be exploited for
# real against an isolated, throwaway container instead of just describing
# what an exploit would do.
FROM python:3.12-slim
WORKDIR /app

# curl is the callback client used by the verify stage's out-of-band
# payloads (command injection / deserialization RCE gadgets).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py seed_db.py ./
RUN python seed_db.py

EXPOSE 5000
CMD ["flask", "--app", "app", "run", "--host=0.0.0.0", "--port=5000"]
