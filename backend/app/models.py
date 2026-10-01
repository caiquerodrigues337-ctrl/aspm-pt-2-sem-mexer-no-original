from sqlalchemy import Column, String, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone
import uuid

Base = declarative_base()


class Finding(Base):
    __tablename__ = "findings"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    repo_url = Column(String, nullable=False)

    # Identifica qual ferramenta encontrou a vulnerabilidade.
    # Ex.: semgrep, trivy ou gitleaks.
    fonte = Column(String, default="semgrep")

    rule_id = Column(String)
    severity = Column(String)
    file_path = Column(String)
    line = Column(Float)
    message = Column(Text)

    ai_fix = Column(Text)

    # None = ainda não validado
    # True = fix passou na validação
    # False = fix não passou na validação
    fix_validado = Column(Boolean, nullable=True)

    pride_score = Column(Float, default=0.0)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )