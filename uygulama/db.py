import os
import pymysql
from pymysql.cursors import DictCursor

PRIMARY_HOST = os.getenv("DB_YAZMA_HOST", os.getenv("MYSQL_PRIMARY_HOST", "mysql-primary"))
PRIMARY_PORT = int(os.getenv("DB_YAZMA_PORT", os.getenv("DB_PORT", "3306")))

REPLICA_HOST = os.getenv("DB_OKUMA_HOST", os.getenv("MYSQL_REPLICA_HOST", "mysql-replica"))
REPLICA_PORT = int(os.getenv("DB_OKUMA_PORT", os.getenv("DB_PORT", "3306")))

DB_USER = os.getenv("DB_KULLANICI", os.getenv("MYSQL_USER", "yemekhane_app"))
DB_PASSWORD = os.getenv("DB_SIFRE", os.getenv("MYSQL_PASSWORD", "Uyg_2026"))
DB_NAME = os.getenv("DB_ADI", os.getenv("MYSQL_DATABASE", "yemekhane"))


def _baglanti_olustur(host: str, port: int):
    return pymysql.connect(
        host=host,
        port=port,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
    )


def yazma_baglantisi():
    return _baglanti_olustur(PRIMARY_HOST, PRIMARY_PORT)


def okuma_baglantisi():
    try:
        return _baglanti_olustur(REPLICA_HOST, REPLICA_PORT)
    except Exception:
        return _baglanti_olustur(PRIMARY_HOST, PRIMARY_PORT)