# app/main.py
from fastapi import FastAPI
from .middlewares import add_middlewares
from .logger import setup_logging

app = FastAPI()

# Настраиваем логирование
setup_logging()

# Подключаем middleware для защиты
add_middlewares(app)

@app.get("/")
async def index():
    return {"message": "Приложение защищено от атак!"}
