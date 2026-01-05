"""One-off Strix findings loader for local validation."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    # Hardcoded inputs for quick local validation.
    job_id = 107
    run_dir = Path("strix_runs/web-alb-1147898453-us-west-2-elb_2f4d")
    report_format = "json"

    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    from app.db import models
    from app.db.session import SessionLocal, init_db
    from app.services.report_parsers.strix import parse_strix_report
    from app.services.reporting import generate_report

    if not run_dir.exists():
        raise SystemExit(f"Run directory not found: {run_dir}")

    init_db()
    session = SessionLocal()
    try:
        job = session.get(models.ScanJob, job_id)
        if not job:
            raise SystemExit(f"Job not found: {job_id}")

        job.status = "COMPLETED"
        session.commit()

        findings = parse_strix_report(run_dir)
        for finding in findings:
            session.add(
                models.Finding(
                    job_id=job.id,
                    vuln_id=finding.vuln_id,
                    title=finding.title,
                    severity=finding.severity,
                    tags=finding.tags,
                    description=finding.description,
                    solution=finding.solution,
                    evidence=finding.evidence,
                    raw_data=finding.raw_data,
                )
            )
        session.commit()
        print(f"inserted_findings={len(findings)}")

        if job.status not in {"COMPLETED", "FAILED"}:
            raise SystemExit("Job status must be COMPLETED or FAILED to generate report.")
        report = generate_report(session, job.id, report_format)
        print(f"report_id={report.id}")
        print(f"report_path={report.file_path}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
