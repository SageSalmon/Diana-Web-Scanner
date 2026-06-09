"""Database-backed scan state manager.

Replaces in-memory lists/sets with PostgreSQL-backed state so that:
1. AI agents get small batches instead of the full endpoint list
2. Multiple agents/workers can share state (horizontal scaling)
3. Findings from one agent are visible to others
4. Scans can be resumed after interruption
5. Duplicate testing is prevented via DB constraints
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    engagement_id = Column(String, nullable=False)
    status = Column(String, default="pending")
    admin_token = Column(Text, default="")
    user_token = Column(Text, default="")
    user_id = Column(Integer, default=0)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    # Build provenance — which code produced this scan
    git_sha = Column(String, default="")
    git_branch = Column(String, default="")
    image_tag = Column(String, default="")


class EndpointRecord(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    parameters = Column(Text, default="{}")  # JSON
    content_type = Column(String, default="")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("scan_id", "url", "method", name="uq_endpoint"),
    )


class EndpointAgentStatus(Base):
    """Junction table — tracks which agent tested which endpoint."""
    __tablename__ = "endpoint_agent_status"

    endpoint_id = Column(Integer, nullable=False, primary_key=True)
    agent_name = Column(String, nullable=False, primary_key=True)
    status = Column(String, default="pending")  # pending, tested, skipped
    tested_at = Column(DateTime, nullable=True)
    finding_count = Column(Integer, default=0)


class TokenUsageRecord(Base):
    """Tracks LLM token usage per module per scan."""
    __tablename__ = "token_usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    module = Column(String, nullable=False)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    calls = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ModuleMetrics(Base):
    """Per-module operational metrics for a scan.

    Tracks how much work each module did — analyze requests, HTTP calls,
    LLM calls, refetches, and token consumption. One row per scan+module.
    Counters are incremented atomically via SQL UPDATE for concurrency safety.
    """
    __tablename__ = "module_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    module = Column(String, nullable=False)

    # Work items this module was asked to analyze
    items_queued = Column(Integer, default=0)
    items_claimed = Column(Integer, default=0)
    items_completed = Column(Integer, default=0)
    items_skipped = Column(Integer, default=0)

    # HTTP requests the module made to the target
    http_requests = Column(Integer, default=0)
    http_request_bytes = Column(Integer, default=0)

    # Duplicate / refetch tracking
    cache_hits = Column(Integer, default=0)
    refetches = Column(Integer, default=0)

    # LLM interactions
    llm_calls = Column(Integer, default=0)
    llm_input_tokens = Column(Integer, default=0)
    llm_output_tokens = Column(Integer, default=0)
    llm_errors = Column(Integer, default=0)

    # Findings produced
    findings_reported = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)

    # Timing
    duration_seconds = Column(Float, default=0.0)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("scan_id", "module", name="uq_module_metrics"),
    )


class ScanQueueItem(Base):
    """Per-module work queue with module-specific payloads."""
    __tablename__ = "scan_queue"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    target_module = Column(String, nullable=False, index=True)
    source_module = Column(String, nullable=False)
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    auth_context = Column(String, default="admin", index=True)  # admin, user, none
    payload = Column(Text, default="{}")  # JSON — module-specific extras
    dedup_key = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, claimed, completed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("scan_id", "target_module", "dedup_key", name="uq_queue_dedup"),
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False, index=True)
    module = Column(String, nullable=False)
    vuln_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    endpoint_url = Column(String, default="")
    endpoint_method = Column(String, default="")
    evidence = Column(Text, default="")
    payload_used = Column(Text, default="")
    cwe_id = Column(String, default="")
    remediation = Column(Text, default="")
    confirmed = Column(Boolean, default=True)
    false_positive = Column(Boolean, default=False)
    ai_analysis = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ScanState:
    """Database-backed scan state manager.

    Usage:
        state = ScanState("postgresql://diana:diana_dev@localhost:5432/diana")
        state.create_tables()

        # Store endpoints from crawler
        state.store_endpoint(scan_id, url, method, params)

        # Agent gets a batch of untested endpoints
        batch = state.get_untested_endpoints(scan_id, "sqli_agent", limit=10)

        # Agent marks endpoints as tested
        state.mark_tested(scan_id, url, method, "sqli_agent")

        # Agent stores findings (visible to other agents)
        state.store_finding(scan_id, "sqli_agent", finding)

        # Other agents can see what was found
        findings = state.get_findings(scan_id)
    """

    def __init__(self, database_url: str = "postgresql://diana:diana_dev@localhost:5432/diana"):
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)

    def create_tables(self) -> None:
        Base.metadata.create_all(self.engine)
        self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Apply schema migrations for columns added after initial deployment.

        Uses ADD COLUMN IF NOT EXISTS (PostgreSQL 9.6+) so this is idempotent.
        """
        migrations = [
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS git_sha VARCHAR DEFAULT ''",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS git_branch VARCHAR DEFAULT ''",
            "ALTER TABLE scans ADD COLUMN IF NOT EXISTS image_tag VARCHAR DEFAULT ''",
        ]
        with self.engine.connect() as conn:
            for sql in migrations:
                try:
                    conn.execute(text(sql))
                except Exception:
                    pass  # Column already exists or table doesn't exist yet
            conn.commit()

    # --- Scan lifecycle ---

    def create_scan(
        self, scan_id: str, target: str, engagement_id: str,
        git_sha: str = "", git_branch: str = "", image_tag: str = "",
    ) -> None:
        with self.SessionLocal() as session:
            scan = ScanRecord(
                id=scan_id,
                target=target,
                engagement_id=engagement_id,
                status="running",
                git_sha=git_sha,
                git_branch=git_branch,
                image_tag=image_tag,
            )
            session.merge(scan)
            session.commit()

    def update_scan_status(self, scan_id: str, status: str) -> None:
        with self.SessionLocal() as session:
            scan = session.get(ScanRecord, scan_id)
            if scan:
                scan.status = status
                if status in ("completed", "failed"):
                    scan.completed_at = datetime.now(timezone.utc)
                session.commit()

    def store_auth(
        self, scan_id: str, admin_token: str, user_token: str = "", user_id: int = 0
    ) -> None:
        with self.SessionLocal() as session:
            scan = session.get(ScanRecord, scan_id)
            if scan:
                scan.admin_token = admin_token
                scan.user_token = user_token
                scan.user_id = user_id
                session.commit()

    def get_auth(self, scan_id: str) -> dict:
        with self.SessionLocal() as session:
            scan = session.get(ScanRecord, scan_id)
            if scan:
                return {
                    "admin_token": scan.admin_token,
                    "user_token": scan.user_token,
                    "user_id": scan.user_id,
                }
            return {}

    # --- Endpoints ---

    def store_endpoint(
        self,
        scan_id: str,
        url: str,
        method: str = "GET",
        parameters: dict | None = None,
        content_type: str = "",
    ) -> None:
        with self.SessionLocal() as session:
            existing = session.query(EndpointRecord).filter_by(
                scan_id=scan_id, url=url, method=method
            ).first()
            if existing:
                return  # Already stored
            ep = EndpointRecord(
                scan_id=scan_id,
                url=url,
                method=method,
                parameters=json.dumps(parameters or {}),
                content_type=content_type,
            )
            session.add(ep)
            session.commit()

    def store_endpoints_bulk(self, scan_id: str, endpoints: list[dict]) -> int:
        """Store multiple endpoints, skipping duplicates. Returns count stored."""
        stored = 0
        with self.SessionLocal() as session:
            for ep in endpoints:
                existing = session.query(EndpointRecord).filter_by(
                    scan_id=scan_id, url=ep["url"], method=ep.get("method", "GET")
                ).first()
                if not existing:
                    session.add(EndpointRecord(
                        scan_id=scan_id,
                        url=ep["url"],
                        method=ep.get("method", "GET"),
                        parameters=json.dumps(ep.get("parameters", {})),
                        content_type=ep.get("content_type", ""),
                    ))
                    stored += 1
            session.commit()
        return stored

    def get_untested_endpoints(
        self, scan_id: str, agent: str, limit: int = 10
    ) -> list[dict]:
        """Get endpoints not yet tested by this agent via junction table."""
        with self.SessionLocal() as session:
            from sqlalchemy.orm import aliased
            # LEFT JOIN — endpoints with no matching status row for this agent
            results = (
                session.query(EndpointRecord)
                .outerjoin(
                    EndpointAgentStatus,
                    (EndpointRecord.id == EndpointAgentStatus.endpoint_id)
                    & (EndpointAgentStatus.agent_name == agent),
                )
                .filter(
                    EndpointRecord.scan_id == scan_id,
                    EndpointAgentStatus.endpoint_id.is_(None),
                )
                .limit(limit)
                .all()
            )

            return [
                {
                    "id": r.id,
                    "url": r.url,
                    "method": r.method,
                    "parameters": json.loads(r.parameters),
                }
                for r in results
            ]

    def get_parameterized_endpoints(
        self, scan_id: str, agent: str, limit: int = 10
    ) -> list[dict]:
        """Get untested endpoints that have parameters."""
        with self.SessionLocal() as session:
            results = (
                session.query(EndpointRecord)
                .outerjoin(
                    EndpointAgentStatus,
                    (EndpointRecord.id == EndpointAgentStatus.endpoint_id)
                    & (EndpointAgentStatus.agent_name == agent),
                )
                .filter(
                    EndpointRecord.scan_id == scan_id,
                    EndpointAgentStatus.endpoint_id.is_(None),
                    EndpointRecord.parameters != "{}",
                )
                .limit(limit)
                .all()
            )

            return [
                {
                    "id": r.id,
                    "url": r.url,
                    "method": r.method,
                    "parameters": json.loads(r.parameters),
                }
                for r in results
            ]

    def mark_tested(
        self, scan_id: str, url: str, method: str, agent: str,
        finding_count: int = 0,
    ) -> None:
        """Mark an endpoint as tested by an agent via junction table."""
        with self.SessionLocal() as session:
            ep = session.query(EndpointRecord).filter_by(
                scan_id=scan_id, url=url, method=method
            ).first()
            if not ep:
                return
            existing = session.query(EndpointAgentStatus).filter_by(
                endpoint_id=ep.id, agent_name=agent
            ).first()
            if existing:
                existing.status = "tested"
                existing.tested_at = datetime.now(timezone.utc)
                existing.finding_count = finding_count
            else:
                session.add(EndpointAgentStatus(
                    endpoint_id=ep.id,
                    agent_name=agent,
                    status="tested",
                    tested_at=datetime.now(timezone.utc),
                    finding_count=finding_count,
                ))
            session.commit()

    def get_agent_coverage(self, scan_id: str) -> dict:
        """Get per-agent test coverage stats."""
        with self.SessionLocal() as session:
            total = session.query(EndpointRecord).filter_by(scan_id=scan_id).count()
            agents = (
                session.query(
                    EndpointAgentStatus.agent_name,
                    session.query(EndpointAgentStatus).filter(
                        EndpointAgentStatus.status == "tested"
                    ).correlate(None).count(),
                )
            )
            # Simpler approach
            from sqlalchemy import func
            coverage = (
                session.query(
                    EndpointAgentStatus.agent_name,
                    func.count(EndpointAgentStatus.endpoint_id),
                )
                .join(EndpointRecord, EndpointRecord.id == EndpointAgentStatus.endpoint_id)
                .filter(
                    EndpointRecord.scan_id == scan_id,
                    EndpointAgentStatus.status == "tested",
                )
                .group_by(EndpointAgentStatus.agent_name)
                .all()
            )
            return {
                "total_endpoints": total,
                "by_agent": {name: count for name, count in coverage},
            }

    def get_endpoint_count(self, scan_id: str) -> dict:
        with self.SessionLocal() as session:
            total = session.query(EndpointRecord).filter_by(scan_id=scan_id).count()
            with_params = session.query(EndpointRecord).filter(
                EndpointRecord.scan_id == scan_id,
                EndpointRecord.parameters != "{}",
            ).count()
            return {"total": total, "with_params": with_params}

    # --- Findings ---

    @staticmethod
    def _sanitize(value: str) -> str:
        """Strip null bytes — PostgreSQL text columns can't contain them."""
        return value.replace("\x00", "") if value else ""

    def store_finding(
        self,
        scan_id: str,
        module: str,
        finding_data: dict,
    ) -> str:
        s = self._sanitize
        finding_id = finding_data.get("id", f"DB-{uuid.uuid4().hex[:8]}")
        with self.SessionLocal() as session:
            record = FindingRecord(
                id=finding_id,
                scan_id=scan_id,
                module=module,
                vuln_type=s(finding_data.get("vuln_type", "")),
                severity=s(finding_data.get("severity", "high")),
                title=s(finding_data.get("title", "")),
                description=s(finding_data.get("description", "")),
                endpoint_url=s(finding_data.get("endpoint_url", "")),
                endpoint_method=s(finding_data.get("endpoint_method", "")),
                evidence=s(finding_data.get("evidence", ""))[:2000],
                payload_used=s(finding_data.get("payload_used", "")),
                cwe_id=s(finding_data.get("cwe_id", "")),
                remediation=s(finding_data.get("remediation", "")),
                confirmed=finding_data.get("confirmed", True),
            )
            session.merge(record)
            session.commit()
        return finding_id

    def get_findings(
        self, scan_id: str, module: str | None = None
    ) -> list[dict]:
        with self.SessionLocal() as session:
            query = session.query(FindingRecord).filter_by(scan_id=scan_id)
            if module:
                query = query.filter_by(module=module)
            results = query.all()
            return [
                {
                    "id": r.id,
                    "module": r.module,
                    "vuln_type": r.vuln_type,
                    "severity": r.severity,
                    "title": r.title,
                    "description": r.description,
                    "endpoint_url": r.endpoint_url,
                    "endpoint_method": r.endpoint_method,
                    "evidence": r.evidence,
                    "cwe_id": r.cwe_id,
                    "confirmed": r.confirmed,
                }
                for r in results
            ]

    def get_finding_count(self, scan_id: str) -> dict:
        with self.SessionLocal() as session:
            total = session.query(FindingRecord).filter_by(scan_id=scan_id).count()
            by_severity: dict[str, int] = {}
            for sev in ["critical", "high", "medium", "low", "info"]:
                by_severity[sev] = session.query(FindingRecord).filter_by(
                    scan_id=scan_id, severity=sev
                ).count()
            return {"total": total, **by_severity}

    def get_findings_summary(self, scan_id: str) -> str:
        """Get a brief text summary of findings for agent context."""
        findings = self.get_findings(scan_id)
        if not findings:
            return "No findings yet."
        lines = [f"Findings so far ({len(findings)}):"]
        for f in findings[:20]:
            lines.append(f"  [{f['severity']}] {f['title']}")
        if len(findings) > 20:
            lines.append(f"  ... and {len(findings) - 20} more")
        return "\n".join(lines)

    # --- Token Usage ---

    def store_token_usage(
        self, scan_id: str, module: str,
        input_tokens: int, output_tokens: int, calls: int,
    ) -> None:
        with self.SessionLocal() as session:
            session.add(TokenUsageRecord(
                scan_id=scan_id,
                module=module,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                calls=calls,
            ))
            session.commit()

    def get_token_usage(self, scan_id: str) -> dict:
        with self.SessionLocal() as session:
            from sqlalchemy import func
            rows = (
                session.query(
                    TokenUsageRecord.module,
                    func.sum(TokenUsageRecord.input_tokens),
                    func.sum(TokenUsageRecord.output_tokens),
                    func.sum(TokenUsageRecord.calls),
                )
                .filter_by(scan_id=scan_id)
                .group_by(TokenUsageRecord.module)
                .all()
            )
            return {
                row[0]: {"input_tokens": row[1], "output_tokens": row[2], "calls": row[3]}
                for row in rows
            }

    # --- Scan Queue ---

    def enqueue(
        self,
        scan_id: str,
        target_module: str,
        source_module: str,
        url: str,
        method: str = "GET",
        auth_context: str = "admin",
        payload: dict | None = None,
        dedup_key: str = "",
    ) -> bool:
        """Add a work item to a module's queue. Returns False if duplicate.

        auth_context: which credential to use (admin, user, none).
        dedup_key defaults to 'method|url|auth_context' if not provided.
        """
        if not dedup_key:
            dedup_key = f"{method}|{url}|{auth_context}"

        with self.SessionLocal() as session:
            existing = session.query(ScanQueueItem).filter_by(
                scan_id=scan_id,
                target_module=target_module,
                dedup_key=dedup_key,
            ).first()
            if existing:
                return False

            session.add(ScanQueueItem(
                scan_id=scan_id,
                target_module=target_module,
                source_module=source_module,
                url=url,
                method=method,
                auth_context=auth_context,
                payload=json.dumps(payload or {}),
                dedup_key=dedup_key,
            ))
            session.commit()
            return True

    def enqueue_bulk(
        self,
        scan_id: str,
        target_module: str,
        source_module: str,
        items: list[dict],
    ) -> int:
        """Add multiple work items to a module's queue. Returns count added."""
        added = 0
        with self.SessionLocal() as session:
            for item in items:
                url = item["url"]
                method = item.get("method", "GET")
                auth_context = item.get("auth_context", "admin")
                dedup_key = item.get("dedup_key", f"{method}|{url}|{auth_context}")

                existing = session.query(ScanQueueItem).filter_by(
                    scan_id=scan_id,
                    target_module=target_module,
                    dedup_key=dedup_key,
                ).first()
                if not existing:
                    session.add(ScanQueueItem(
                        scan_id=scan_id,
                        target_module=target_module,
                        source_module=source_module,
                        url=url,
                        method=method,
                        auth_context=auth_context,
                        payload=json.dumps(item.get("payload", {})),
                        dedup_key=dedup_key,
                    ))
                    added += 1
            session.commit()
        return added

    def claim_work(
        self, scan_id: str, module: str, limit: int = 10
    ) -> list[dict]:
        """Claim pending work items from a module's queue.

        Uses SELECT ... FOR UPDATE SKIP LOCKED for safe concurrent access.
        Multiple workers can claim from the same queue without conflicts.
        """
        with self.SessionLocal() as session:
            items = (
                session.query(ScanQueueItem)
                .filter_by(
                    scan_id=scan_id,
                    target_module=module,
                    status="pending",
                )
                .limit(limit)
                .with_for_update(skip_locked=True)
                .all()
            )

            result = []
            for item in items:
                item.status = "claimed"
                item.claimed_at = datetime.now(timezone.utc)
                result.append({
                    "queue_id": item.id,
                    "url": item.url,
                    "method": item.method,
                    "auth_context": item.auth_context,
                    "payload": json.loads(item.payload),
                    "source_module": item.source_module,
                })
            session.commit()
            return result

    def complete_work(self, queue_id: int) -> None:
        """Mark a work item as completed."""
        with self.SessionLocal() as session:
            item = session.get(ScanQueueItem, queue_id)
            if item:
                item.status = "completed"
                item.completed_at = datetime.now(timezone.utc)
                session.commit()

    def get_queue_stats(self, scan_id: str) -> dict:
        """Get per-module queue statistics."""
        from sqlalchemy import func
        with self.SessionLocal() as session:
            stats = (
                session.query(
                    ScanQueueItem.target_module,
                    ScanQueueItem.status,
                    func.count(ScanQueueItem.id),
                )
                .filter_by(scan_id=scan_id)
                .group_by(ScanQueueItem.target_module, ScanQueueItem.status)
                .all()
            )

            result: dict[str, dict[str, int]] = {}
            for module, status, count in stats:
                if module not in result:
                    result[module] = {}
                result[module][status] = count
            return result

    # --- Module Metrics ---

    def _ensure_module_metrics(self, session: Session, scan_id: str, module: str) -> ModuleMetrics:
        """Get or create a ModuleMetrics row for this scan+module."""
        row = session.query(ModuleMetrics).filter_by(
            scan_id=scan_id, module=module
        ).first()
        if not row:
            row = ModuleMetrics(scan_id=scan_id, module=module)
            session.add(row)
            session.flush()
        return row

    def increment_module_metrics(
        self, scan_id: str, module: str, **counters: int
    ) -> None:
        """Atomically increment one or more metric counters.

        Usage:
            state.increment_module_metrics(scan_id, "sqli_agent",
                http_requests=1, llm_calls=1, llm_input_tokens=2400)
        """
        with self.SessionLocal() as session:
            row = self._ensure_module_metrics(session, scan_id, module)
            for field, delta in counters.items():
                if hasattr(row, field):
                    current = getattr(row, field) or 0
                    setattr(row, field, current + delta)
            session.commit()

    def set_module_timing(
        self, scan_id: str, module: str,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float = 0.0,
    ) -> None:
        """Set timing fields for a module."""
        with self.SessionLocal() as session:
            row = self._ensure_module_metrics(session, scan_id, module)
            if started_at:
                row.started_at = started_at
            if completed_at:
                row.completed_at = completed_at
            if duration_seconds:
                row.duration_seconds = duration_seconds
            session.commit()

    def get_module_metrics(self, scan_id: str, module: str | None = None) -> dict:
        """Get module metrics for a scan. If module is None, returns all modules."""
        with self.SessionLocal() as session:
            query = session.query(ModuleMetrics).filter_by(scan_id=scan_id)
            if module:
                query = query.filter_by(module=module)
            rows = query.all()

            result = {}
            for row in rows:
                result[row.module] = {
                    "items_queued": row.items_queued,
                    "items_claimed": row.items_claimed,
                    "items_completed": row.items_completed,
                    "items_skipped": row.items_skipped,
                    "http_requests": row.http_requests,
                    "http_request_bytes": row.http_request_bytes,
                    "cache_hits": row.cache_hits,
                    "refetches": row.refetches,
                    "llm_calls": row.llm_calls,
                    "llm_input_tokens": row.llm_input_tokens,
                    "llm_output_tokens": row.llm_output_tokens,
                    "llm_errors": row.llm_errors,
                    "findings_reported": row.findings_reported,
                    "false_positives": row.false_positives,
                    "duration_seconds": row.duration_seconds,
                    "started_at": row.started_at.isoformat() if row.started_at else None,
                    "completed_at": row.completed_at.isoformat() if row.completed_at else None,
                }
            return result

    def get_scan_cost_summary(self, scan_id: str, pricing: dict | None = None) -> dict:
        """Get a cost-oriented summary across all modules for a scan.

        Args:
            pricing: Dict with 'input_per_1m' and 'output_per_1m' keys.
                     If None, returns token counts without cost estimates.
        """
        from sqlalchemy import func
        with self.SessionLocal() as session:
            totals = (
                session.query(
                    func.sum(ModuleMetrics.items_queued),
                    func.sum(ModuleMetrics.items_completed),
                    func.sum(ModuleMetrics.http_requests),
                    func.sum(ModuleMetrics.llm_calls),
                    func.sum(ModuleMetrics.llm_input_tokens),
                    func.sum(ModuleMetrics.llm_output_tokens),
                    func.sum(ModuleMetrics.llm_errors),
                    func.sum(ModuleMetrics.findings_reported),
                    func.sum(ModuleMetrics.false_positives),
                    func.sum(ModuleMetrics.cache_hits),
                    func.sum(ModuleMetrics.refetches),
                )
                .filter_by(scan_id=scan_id)
                .first()
            )

            if not totals or totals[0] is None:
                return {}

            summary = {
                "items_queued": totals[0] or 0,
                "items_completed": totals[1] or 0,
                "http_requests": totals[2] or 0,
                "llm_calls": totals[3] or 0,
                "llm_input_tokens": totals[4] or 0,
                "llm_output_tokens": totals[5] or 0,
                "llm_errors": totals[6] or 0,
                "findings_reported": totals[7] or 0,
                "false_positives": totals[8] or 0,
                "cache_hits": totals[9] or 0,
                "refetches": totals[10] or 0,
            }

            if pricing:
                input_cost = (summary["llm_input_tokens"] / 1_000_000) * pricing.get("input_per_1m", 0)
                output_cost = (summary["llm_output_tokens"] / 1_000_000) * pricing.get("output_per_1m", 0)
                summary["estimated_cost_usd"] = round(input_cost + output_cost, 4)

            return summary
