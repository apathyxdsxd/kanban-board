FROM python:3.8-slim-buster

EXPOSE 5000

# Оптимизация работы Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Установка зависимостей Python
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Копирование исходного кода
COPY ./src/ /app/

# Создание непривилегированного пользователя
RUN useradd -m appuser && chown -R appuser /app
USER appuser

# Команда для запуска приложения
CMD ["python", "your_main_file.py"]