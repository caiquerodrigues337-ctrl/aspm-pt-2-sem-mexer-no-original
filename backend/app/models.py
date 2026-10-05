from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    repo_url = Column(
        String,
        nullable=False,
        index=True,
    )

    status = Column(
        String,
        nullable=False,
        default="running",
    )

    total = Column(
        Integer,
        nullable=False,
        default=0,
    )

    semgrep_total = Column(
        Integer,
        nullable=False,
        default=0,
    )

    trivy_total = Column(
        Integer,
        nullable=False,
        default=0,
    )

    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    finished_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Identifica o scan que gerou este finding.
    # nullable=True mantém compatibilidade com findings antigos.
    scan_id = Column(
        String,
        ForeignKey(
            "scans.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    repo_url = Column(
        String,
        nullable=False,
    )

    # Ex.: semgrep, trivy ou gitleaks.
    fonte = Column(
        String,
        default="semgrep",
    )

    rule_id = Column(String)
    severity = Column(String)
    file_path = Column(String)
    line = Column(Float)
    message = Column(Text)

    ai_fix = Column(Text)

    # None = ainda não validado
    # True = fix passou na validação
    # False = fix não passou na validação
    fix_validado = Column(
        Boolean,
        nullable=True,
    )

    pride_score = Column(
        Float,
        default=0.0,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
