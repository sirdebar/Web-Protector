# app/middlewares.py
from fastapi import Request, HTTPException
from starlette.middleware.cors import CORSMiddleware
from .security import is_request_malicious, rate_limit
import yaml

# Загружаем настройки из config.yaml
with open("config/config.yaml") as f:
    config = yaml.safe_load(f)

def add_middlewares(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config["allowed_origins"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def ddos_protection(request: Request, call_next):
        ip = request.client.host
        query_params = str(request.query_params)
        body = await request.body()

        if is_request_malicious(query_params, body.decode("utf-8")):
            raise HTTPException(status_code=403, detail="Запрос заблокирован WAF")

        if not rate_limit(ip):
            raise HTTPException(status_code=429, detail="Слишком много запросов")

        return await call_next(request)
