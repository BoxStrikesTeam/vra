"""SQLite database layer for VRA."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from vra.core.logging import get_logger

log = get_logger("storage.database")


class Base(DeclarativeBase):
    pass


class ProjectModel(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    path = Column(String)
    languages = Column(String)
    build_system = Column(String)
    created_at = Column(DateTime)


class RunModel(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    commit_hash = Column(String)
    branch = Column(String)
    profile = Column(String)
    timestamp = Column(DateTime)
    status = Column(String)
    project = relationship("ProjectModel")


class FindingModel(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    finding_id = Column(String, unique=True)
    run_id = Column(Integer, ForeignKey("runs.id"))
    title = Column(String)
    category = Column(String)
    cwe = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    priority_score = Column(Float)
    file_path = Column(String)
    line = Column(Integer)
    function_name = Column(String)
    tools = Column(String)
    reachability = Column(String)
    controllability = Column(String)
    status = Column(String)
    notes = Column(Text)
    fingerprint = Column(String)
    attack_surface = Column(String)
    source_snippet = Column(Text)
    vendor_source = Column(String)
    call_chain = Column(Text)
    dataflow = Column(Text)
    created_at = Column(DateTime)
    run = relationship("RunModel")


class EvidenceModel(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    type = Column(String)
    source = Column(String)
    detail = Column(Text)
    finding = relationship("FindingModel")


class ReportModel(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id"))
    format = Column(String)
    path = Column(String)
    created_at = Column(DateTime)
    run = relationship("RunModel")


class Database:
    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = Path("vra.db")
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        # Soft-migrate: add any missing columns to already-existent tables so a
        # schema evolution on a previous VRA run does not break reads/writes.
        self._ensure_columns()
        self._session_factory = sessionmaker(bind=self.engine)

    def _ensure_columns(self) -> None:
        """Add columns to existing tables that are declared on the models now."""
        try:
            inspector = inspect(self.engine)
            with self.engine.begin() as conn:
                for table in Base.metadata.sorted_tables:
                    existing = {c["name"] for c in inspector.get_columns(table.name)}
                    for column in table.columns:
                        if column.name not in existing:
                            dtype = str(column.type.compile(dialect=self.engine.dialect))
                            conn.execute(
                                text(
                                    f"ALTER TABLE {table.name} "
                                    f"ADD COLUMN {column.name} {dtype}"
                                )
                            )
                            log.info("Migrated column %s.%s", table.name, column.name)
        except Exception as e:  # pragma: no cover - best effort
            log.debug("Column migration skipped: %s", e)

    def get_session(self) -> Session:
        return self._session_factory()

    def save_finding(self, finding_model: FindingModel) -> None:
        with self.get_session() as session:
            session.add(finding_model)
            session.commit()

    def get_findings(self, run_id: int | None = None, limit: int = 100) -> list[FindingModel]:
        with self.get_session() as session:
            query = session.query(FindingModel)
            if run_id is None:
                latest = session.query(RunModel.id).order_by(RunModel.id.desc()).first()
                run_id = latest[0] if latest else None
            if run_id is not None:
                query = query.filter_by(run_id=run_id)
            return query.order_by(FindingModel.priority_score.desc()).limit(limit).all()

    def get_finding_by_id(self, finding_id: str) -> FindingModel | None:
        with self.get_session() as session:
            return session.query(FindingModel).filter_by(finding_id=finding_id).first()
