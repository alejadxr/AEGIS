import logging
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.config import settings

logger = logging.getLogger(__name__)


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.AEGIS_ENV == "development",
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=300,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    """Run on startup to verify database connectivity and log configuration."""
    logger.info(f"Database URL: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    logger.info("PostgreSQL: pool_size=20, max_overflow=10, pool_pre_ping=True")

    async with engine.begin() as conn:
        result = await conn.exec_driver_sql("SELECT version()")
        version = result.scalar()
        logger.info(f"PostgreSQL version: {version}")


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
