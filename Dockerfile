FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN useradd --system --uid 10001 proxyuser

USER proxyuser

EXPOSE 5000 8888

CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "2", "--access-logfile", "-", "admin:create_app()"]