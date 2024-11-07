# app/logger.py
import logging
import yaml

# Загрузка конфигурации
with open("config/config.yaml") as f:
    config = yaml.safe_load(f)

LOG_FILE = config["log_file"]

def setup_logging():
    """Настраивает логирование заблокированных запросов"""
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(message)s"
    )

def log_blocked_request(ip: str, reason: str):
    """Логирует заблокированные запросы с IP и причиной блокировки"""
    logging.info(f"Blocked request from {ip}: {reason}")
