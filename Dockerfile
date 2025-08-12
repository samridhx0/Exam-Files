# Minimal PHP runtime with SQLite
FROM php:8.3-cli

# Enable SQLite extensions
RUN docker-php-ext-install pdo_sqlite sqlite3

WORKDIR /app
COPY . /app

# Render provides $PORT; default 8080 for local runs
EXPOSE 8080
CMD ["sh", "-c", "php -S 0.0.0.0:${PORT:-8080} -t /app"]
