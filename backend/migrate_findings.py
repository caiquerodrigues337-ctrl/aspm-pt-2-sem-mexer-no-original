from sqlalchemy import text

from app.database import SessionLocal


def main():
    db = SessionLocal()

    try:
        print("[INFO] Atualizando tabela findings...")

        db.execute(
            text(
                """
                ALTER TABLE findings
                ADD COLUMN IF NOT EXISTS fonte VARCHAR
                DEFAULT 'semgrep';
                """
            )
        )

        db.execute(
            text(
                """
                ALTER TABLE findings
                ADD COLUMN IF NOT EXISTS fix_validado BOOLEAN;
                """
            )
        )

        db.commit()

        print("[OK] Migração concluída.")
        print("[OK] Coluna 'fonte' verificada.")
        print("[OK] Coluna 'fix_validado' verificada.")

    except Exception as erro:
        db.rollback()
        print(f"[ERRO] Falha na migração: {erro}")

    finally:
        db.close()


if __name__ == "__main__":
    main()