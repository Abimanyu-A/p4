# syntax=docker/dockerfile:1

FROM node:22-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app

RUN groupadd --system p4 && useradd --system --gid p4 --home-dir /app p4

COPY pyproject.toml requirements.txt README.md ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY sample_repos/ ./sample_repos/
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

RUN pip install --no-cache-dir --no-deps -e .

RUN mkdir -p run_artifacts && chown -R p4:p4 /app
USER p4

EXPOSE 8000
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
