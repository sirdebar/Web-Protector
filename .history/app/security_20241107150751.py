# app/security.py
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

# Регулярные выражения для обнаружения вредоносных шаблонов
SQL_INJECTION_PATTERN = re.compile(r"(union|select|insert|delete|drop|update|alter|exec|--|;)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script>|</script>|javascript:|onerror=|onload=|alert\()", re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(r"(;|\||&&|`|>|<|\$\(.*\)|\$\{.*\})", re.IGNORECASE)

def is_request_malicious(query: str, body: str) -> bool:
    """Проверяет запрос на наличие SQL-инъекций, XSS и командной инъекции"""
    return any([
        SQL_INJECTION_PATTERN.search(query),
        SQL_INJECTION_PATTERN.search(body),
        XSS_PATTERN.search(query),
        XSS_PATTERN.search(body),
        COMMAND_INJECTION_PATTERN.search(query),
        COMMAND_INJECTION_PATTERN.search(body)
    ])

def rate_limit(ip: str) -> bool:
    """Проверка лимита запросов для IP"""
    current_time = int(time.time())
    key = f"rate_limit:{ip}:{current_time // TIME_WINDOW}"
    requests = redis_client.incr(key)
    if requests == 1:
        redis_client.expire(key, TIME_WINDOW)
    return requests <= RATE_LIMIT
