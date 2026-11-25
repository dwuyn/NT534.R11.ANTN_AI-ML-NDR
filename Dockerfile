FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
COPY ndr ./ndr
RUN pip install --no-cache-dir .
COPY models /models
COPY artifacts/smoke /opt/ndr/smoke
ENTRYPOINT ["ndr"]
