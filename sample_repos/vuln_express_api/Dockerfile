# Sandbox image for P4's own verify stage — see vuln_flask_api/Dockerfile
# for the rationale. Runs app.js unmodified.
FROM node:22-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY app.js ./
COPY routes ./routes

EXPOSE 3000
CMD ["node", "app.js"]
