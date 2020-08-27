from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker

DB_URI = "postgresql+psycopg2://postgres:ssh_manager@localhost/ssh_manager_dev"
engine = create_engine(DB_URI, echo=True)
db_session = scoped_session(
    sessionmaker(autocommit=False, autoflush=False, bind=engine)
)

Base = declarative_base()
Base.query = db_session.query_property()


def init_db() -> None:
    """
    Creates all the tables in db.

    :return: None
    """

    Base.metadata.create_all(bind=engine)
