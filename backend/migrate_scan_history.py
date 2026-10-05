"""
Migração para adicionar histórico de scans à CodeShield.

Execute dentro da pasta backend:

    python migrate_scan_history.py
"""

from sqlalchemy import text

from app.database import SessionLocal


def main():
    db = SessionLocal()

    try:
        print("[INFO] Criando estrutura de histórico de scans...")

        # 1. Cria a tabela de scans.
        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id VARCHAR PRIMARY KEY,
                    repo_url VARCHAR NOT NULL,
                    status VARCHAR NOT NULL DEFAULT 'running',
                    total INTEGER NOT NULL DEFAULT 0,
                    semgrep_total INTEGER NOT NULL DEFAULT 0,
                    trivy_total INTEGER NOT NULL DEFAULT 0,
                    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    finished_at TIMESTAMP WITH TIME ZONE NULL
                );
                """
            )
        )

        # 2. Índice para buscar rapidamente o histórico de um repo.
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_scans_repo_url
                ON scans (repo_url);
                """
            )
        )

        # 3. Liga findings a um scan.
        db.execute(
            text(
                """
                ALTER TABLE findings
                ADD COLUMN IF NOT EXISTS scan_id VARCHAR NULL;
                """
            )
        )

        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_findings_scan_id
                ON findings (scan_id);
                """
            )
        )

        # 4. Cria a FK apenas se ela ainda não existir.
        db.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conname = 'fk_findings_scan_id'
                    ) THEN
                        ALTER TABLE findings
                        ADD CONSTRAINT fk_findings_scan_id
                        FOREIGN KEY (scan_id)
                        REFERENCES scans(id)
                        ON DELETE CASCADE;
                    END IF;
                END
                $$;
                """
            )
        )

        db.commit()

        print("[OK] Tabela scans pronta.")
        print("[OK] Coluna findings.scan_id pronta.")
        print("[OK] Histórico de scans habilitado.")

    except Exception as erro:
        db.rollback()
        print(f"[ERRO] Falha na migração: {erro}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
