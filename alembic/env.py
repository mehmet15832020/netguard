import os
import sys
from logging.config import fileConfig
from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print(
        "HATA: DATABASE_URL ortam değişkeni tanımlı değil.\n"
        "Örnek: DATABASE_URL=postgresql://netguard:şifre@localhost:5432/netguard alembic upgrade head",
        file=sys.stderr,
    )
    sys.exit(1)


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from sqlalchemy import create_engine

    url = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
