FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so Docker can cache this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Remove Windows line endings (CRLF) from the start script, in case it was edited on Windows
RUN sed -i 's/\r$//' entrypoint.sh
RUN python manage.py collectstatic --noinput

# Run as a normal user, not root (if the app is ever compromised, the attacker is not root)
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["sh", "entrypoint.sh"]
