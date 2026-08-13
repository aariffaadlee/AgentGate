"""Static checks for the Compose and container security baseline."""

from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_compose_keeps_database_internal_and_bounds_services() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    postgres = compose["services"]["postgres"]
    api = compose["services"]["api"]
    opa = compose["services"]["opa"]
    frontend = compose["services"]["frontend"]

    assert compose["networks"]["agentgate-internal"]["internal"] is True
    assert postgres["image"] == "postgres:18.4-alpine3.24"
    assert "ports" not in postgres
    assert postgres["mem_limit"] == "512m"
    assert postgres["pids_limit"] == 200
    assert "no-new-privileges:true" in postgres["security_opt"]
    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert api["read_only"] is True
    assert api["mem_limit"] == "512m"
    assert api["pids_limit"] == 100
    assert "no-new-privileges:true" in api["security_opt"]
    assert "./synthetic_data/documents.json:/synthetic_data/documents.json:ro" in api["volumes"]
    assert "./synthetic_data/tickets.json:/synthetic_data/tickets.json:ro" in api["volumes"]
    assert "./synthetic_data/database.json:/synthetic_data/database.json:ro" in api["volumes"]
    assert "./synthetic_data/sandbox:/synthetic_data/sandbox" in api["volumes"]
    assert "audit-checkpoint:/audit-checkpoint" in api["volumes"]
    assert "./evaluations/scenarios:/evaluations/scenarios:ro" in api["volumes"]
    assert "./scripts:/scripts:ro" in api["volumes"]
    assert "evaluation-reports:/evaluations/reports" in api["volumes"]
    assert "audit-checkpoint" in compose["volumes"]
    assert "evaluation-reports" in compose["volumes"]
    assert opa["image"] == "openpolicyagent/opa:1.18.2-static"
    assert "ports" not in opa
    assert opa["read_only"] is True
    assert opa["mem_limit"] == "128m"
    assert opa["pids_limit"] == 50
    assert "no-new-privileges:true" in opa["security_opt"]
    assert "./policies:/policies:ro" in opa["volumes"]
    assert api["depends_on"]["opa"]["condition"] == "service_healthy"
    assert api["healthcheck"]["test"][:2] == ["CMD", "python"]
    assert frontend["ports"] == ["127.0.0.1:5173:8080"]
    assert frontend["read_only"] is True
    assert frontend["mem_limit"] == "128m"
    assert frontend["pids_limit"] == 50
    assert "no-new-privileges:true" in frontend["security_opt"]
    assert frontend["depends_on"]["api"]["condition"] == "service_healthy"


def test_frontend_container_is_unprivileged_and_sets_browser_security_headers() -> None:
    dockerfile = (PROJECT_ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    nginx = (PROJECT_ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")

    assert dockerfile.startswith("FROM node:24.19.0-alpine3.23 AS build\n")
    assert "FROM nginx:1.29.4-alpine3.23" in dockerfile
    assert "USER 101:101" in dockerfile
    assert "listen 8080;" in nginx
    assert "Content-Security-Policy" in nginx
    assert "frame-ancestors 'none'" in nginx
    assert 'X-Content-Type-Options "nosniff"' in nginx
    assert "proxy_pass http://api:8000/;" in nginx


def test_backend_container_uses_pinned_python_and_unprivileged_user() -> None:
    dockerfile = (PROJECT_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.startswith("FROM python:3.12.13-slim-bookworm\n")
    assert '"pip==26.2.1"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "mkdir -p /audit-checkpoint /evaluations/reports" in dockerfile
    assert "chown 10001:10001 /audit-checkpoint /evaluations/reports" in dockerfile
    assert "--no-access-log" in dockerfile


def test_local_secrets_and_virtual_environment_are_ignored() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    assert ".env" in gitignore
    assert ".venv/" in gitignore
    assert "*.pem" in gitignore
    assert "change-me-local-only" in example
    assert "example" in example.lower() or "fake" in example.lower()
    assert "AGENTGATE_TOKEN_SIGNING_KEY_B64" in example
    assert "AGENTGATE_ADMIN_BOOTSTRAP_SECRET" in example
    assert "AGENTGATE_SYNTHETIC_DATA_ROOT=/synthetic_data" in example


def test_opa_policy_and_rule_tests_are_version_controlled() -> None:
    policy = (PROJECT_ROOT / "policies" / "agentgate.rego").read_text(encoding="utf-8")
    policy_tests = (PROJECT_ROOT / "policies" / "tests" / "agentgate_test.rego").read_text(
        encoding="utf-8"
    )

    assert "default decision := {" in policy
    assert '"reason_codes": ["DEFAULT_DENY"]' in policy
    assert "HIGH_RISK_APPROVAL_REQUIRED" in policy
    assert "UNTRUSTED_ONLY_SENSITIVE_INTENT" in policy
    assert policy_tests.count("test_") >= 20
    assert "test_default_deny_for_incomplete_input" in policy_tests


def test_ci_defines_pinned_quality_security_policy_and_compose_gates() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "backend:" in workflow
    assert "frontend:" in workflow
    assert "policy:" in workflow
    assert "codeql:" in workflow
    assert "compose:" in workflow
    assert "pip_audit --skip-editable" in workflow
    assert "python scripts/check_repository_secrets.py" in workflow
    assert "opa test policies --coverage --threshold 90" in workflow
    assert "pnpm audit --prod --audit-level high" in workflow
    assert "docker compose up --detach --wait" in workflow
    assert "python scripts/run_demo.py" in workflow
    for line in workflow.splitlines():
        if line.lstrip().startswith("uses:"):
            reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
            assert "@" in reference
            assert len(reference.rsplit("@", 1)[1]) == 40


def test_phase9_security_operator_and_portfolio_artifacts_are_present() -> None:
    required = [
        "SECURITY.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "docs/api.md",
        "docs/security-model.md",
        "docs/demonstration.md",
        "docs/resume-summary.md",
        "docs/phase-9-explained.md",
        "docs/assets/phase-8-dashboard.png",
        "demo_agent/client.py",
        "scripts/run_demo.py",
    ]
    assert all((PROJECT_ROOT / relative).is_file() for relative in required)

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    for phrase in (
        "Why authorization lives outside the model",
        "```mermaid",
        "Trust boundaries",
        "Start with Docker Compose",
        "Demonstration workflow",
        "Decision examples",
        "Recorded offline deterministic policy-contract baseline",
        "Known limitations and disclaimer",
        "synthetic local fixture",
    ):
        assert phrase in readme
