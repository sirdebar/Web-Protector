from fastapi import Request, HTTPException
from starlette.middleware.cors import CORSMiddleware
import redis
import re
import time
import yaml

# Загружаем настройки из config.yaml
with open("config/config.yaml") as f:
    config = yaml.safe_load(f)

RATE_LIMIT = config["rate_limit"]
TIME_WINDOW = config["time_window"]

redis_client = redis.StrictRedis(host="redis", port=6379, db=0)

SQL_INJECTION_PATTERN = re.compile(r"(union|select|insert|delete|drop|update|alter)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script>|</script>|javascript:|onerror=|onload=)", re.IGNORECASE)

def is_request_malicious(query: str, body: str) -> bool:
    """Проверяет запрос на наличие SQL-инъекций и XSS-атак"""
    return bool(SQL_INJECTION_PATTERN.search(query) or XSS_PATTERN.search(body))

def rate_limit(ip: str) -> bool:
    """Проверка лимита запросов для IP"""
    current_time = int(time.time())
    key = f"rate_limit:{ip}:{current_time // TIME_WINDOW}"
    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, TIME_WINDOW)
    return requests <= RATE_LIMIT

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
