FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt && chown 10001:10001 /app
COPY --chown=10001:10001 . /app
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["sh", "-c", "python manage.py migrate --noinput --settings=config.settings.security_lab && python manage.py seed_security_lab --settings=config.settings.security_lab && exec python manage.py runserver 0.0.0.0:8001 --insecure --noreload --settings=config.settings.security_lab"]
