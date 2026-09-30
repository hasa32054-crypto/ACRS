FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Engine, lifecycle and Phase B tests are stdlib-only and run on every build; the API suite runs with `make test`.
RUN python -m pytest -q tests/test_engines.py tests/test_lifecycle.py tests/test_phase_b.py
RUN useradd -r -u 10001 acrs && chown -R acrs /app
USER acrs
EXPOSE 8000
ENTRYPOINT ["sh", "/app/entrypoint.sh"]
