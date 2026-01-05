"""Strix scan dashboard page."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import streamlit as st

from lib.api_client import APIClient
from lib.report_viewer import fetch_report_json, render_report


@st.cache_data(ttl=5)
def _load_targets(base_url: str) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_targets(limit=1000, offset=0)


def _format_target_label(target: Dict[str, Any]) -> str:
    info = target.get("connection_info") or {}
    name = target.get("name") or f"target-{target.get('id')}"
    target_type = target.get("type") or ""
    detail = info.get("url") or info.get("path") or info.get("host") or info.get("ip") or ""
    return f"{name} (id={target.get('id')}, {target_type}, {detail})"


def _build_config(
    *,
    scan_mode: str,
    instruction: str,
    instruction_file: str,
    non_interactive: bool,
    run_name: str,
    timeout: int,
    overrides: Dict[str, Any],
) -> Dict[str, Any]:
    config: Dict[str, Any] = {
        "scan_mode": scan_mode,
        "non_interactive": non_interactive,
        "timeout": int(timeout),
    }
    if instruction:
        config["instruction"] = instruction
    if instruction_file:
        config["instruction_file"] = instruction_file
    if run_name:
        config["run_name"] = run_name
    config.update({key: value for key, value in overrides.items() if value not in ("", None)})
    return config


def _load_reports(client: APIClient, job_id: int) -> List[Dict[str, Any]]:
    return client.list_reports(job_id=job_id, limit=200, offset=0)


def _format_report_label(report: Dict[str, Any]) -> str:
    report_id = report.get("id")
    report_format = report.get("format")
    generated_at = report.get("generated_at")
    return f"id={report_id} | {report_format} | {generated_at}"


def _rerun() -> None:
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


def _read_log_tail(path: Path, max_bytes: int = 200_000) -> str:
    if not path.exists():
        return ""
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(-max_bytes, os.SEEK_END)
        data = handle.read()
    return data.decode("utf-8", errors="replace")


def _parse_live_status(text: str) -> Dict[str, str]:
    status: Dict[str, str] = {}
    for line in _clean_log_lines(text):
        if line.startswith("Target:"):
            status["target"] = line.split("Target:", 1)[1].strip()
        if line.startswith("Results will be saved to:"):
            status["results_path"] = line.split("Results will be saved to:", 1)[1].strip()
        if "Running penetration test" in line or "Completed" in line or "Failed" in line:
            status["status_line"] = line.strip()
        match = re.search(r"Vulnerabilities:\s*([0-9]+)", line)
        if match:
            status["vulnerabilities"] = match.group(1)
        match = re.search(r"Model:\s*([A-Za-z0-9/._-]+)", line)
        if match:
            status["model"] = match.group(1)
        match = re.search(r"Agents:\s*([0-9]+).*Tools:\s*([0-9]+)", line)
        if match:
            status["agents"] = match.group(1)
            status["tools"] = match.group(2)
        match = re.search(r"Input:\s*([0-9.]+[KMG]?).*Cached:\s*([0-9.]+[KMG]?)", line)
        if match:
            status["input"] = match.group(1)
            status["cached"] = match.group(2)
        match = re.search(r"Output:\s*([0-9.]+[KMG]?).*Cost:\s*\\$([0-9.]+)", line)
        if match:
            status["output"] = match.group(1)
            status["cost"] = f"${match.group(2)}"
    return status


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def _clean_log_lines(text: str) -> List[str]:
    cleaned: List[str] = []
    for raw_line in _strip_ansi(text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("╭", "╰")) and "──" in line:
            continue
        line = line.strip("│").strip()
        if line and not set(line) <= {"─"}:
            cleaned.append(line)
    return cleaned


def _extract_latest_block(text: str, title: str) -> str:
    raw = _strip_ansi(text)
    lines = raw.splitlines()
    indexes = [i for i, line in enumerate(lines) if title in line]
    if not indexes:
        return ""
    start = indexes[-1]
    end = None
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.startswith("╰") and "─" in line:
            end = i + 1
            break
    block_lines = lines[start:end] if end else lines[start:]
    return "\n".join(block_lines).strip()


def main() -> None:
    st.header("Strix 스캔")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.caption(f"API_BASE_URL = {api_base_url}")

    client = APIClient(api_base_url)

    try:
        targets = _load_targets(api_base_url)
    except Exception as exc:
        st.error(str(exc))
        return

    st.subheader("1) 스캔 유형 선택")
    scan_type = st.selectbox("유형", ["Dynamic (WEB_URL)", "Static (GIT_REPO)"])
    is_dynamic = scan_type.startswith("Dynamic")
    plugin_id = "dynamic_strix_scan" if is_dynamic else "static_strix_scan"

    st.subheader("2) 대상 선택")
    target_type = "WEB_URL" if is_dynamic else "GIT_REPO"
    filtered_targets = [t for t in targets if t.get("type") == target_type]
    target_labels = { _format_target_label(t): t for t in filtered_targets }
    selected_label = st.selectbox(
        f"{target_type} 대상",
        options=list(target_labels.keys()) or ["(등록된 대상이 없습니다)"],
    )
    selected_target = target_labels.get(selected_label)

    st.subheader("3) 스캔 설정")
    scan_mode = st.selectbox("scan_mode", ["deep", "standard", "quick"], index=0)
    instruction = st.text_area("instruction (선택)", value="", height=120)
    instruction_file = st.text_input("instruction_file (선택)", value="")
    non_interactive = st.checkbox("non_interactive", value=True)
    run_name = st.text_input("run_name (선택)", value="")
    timeout = st.number_input("timeout(초)", min_value=60, max_value=7200, value=1800, step=60)

    st.subheader("4) 대상별 오버라이드(선택)")
    overrides: Dict[str, Any] = {}
    if is_dynamic:
        base_url = st.text_input("base_url (선택)", value="")
        if base_url:
            overrides["base_url"] = base_url
    else:
        repo_url = st.text_input("repo_url (선택)", value="")
        repo_path = st.text_input("repo_path (선택)", value="")
        repo_ref = st.text_input("repo_ref (선택)", value="")
        if repo_url:
            overrides["repo_url"] = repo_url
        if repo_path:
            overrides["repo_path"] = repo_path
        if repo_ref:
            overrides["repo_ref"] = repo_ref

    st.subheader("5) 실행")
    if st.button("Strix 스캔 실행"):
        if not selected_target:
            st.error("대상이 필요합니다. 먼저 Target을 등록하세요.")
            return

        scan_config = _build_config(
            scan_mode=scan_mode,
            instruction=instruction,
            instruction_file=instruction_file,
            non_interactive=non_interactive,
            run_name=run_name,
            timeout=int(timeout),
            overrides=overrides,
        )

        payload = {
            "target_id": int(selected_target.get("id")),
            "scan_scope": [plugin_id],
            "scan_config": {plugin_id: scan_config},
            "run_now": True,
        }
        try:
            result = client.create_job(payload)
            st.success(f"Job 생성 완료: id={result.get('id')}")
            st.session_state["strix_last_job_id"] = result.get("id")
            st.session_state["strix_last_run_name"] = run_name.strip()
            st.session_state["strix_last_scan_type"] = "dynamic" if is_dynamic else "static"
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    last_job_id = st.session_state.get("strix_last_job_id")
    if last_job_id:
        st.subheader("6) 진행 상태/결과")
        st.caption(f"현재 Job ID: {last_job_id}")

        col_refresh, col_interval = st.columns(2)
        with col_refresh:
            auto_refresh = st.checkbox("자동 새로고침", value=True, key="strix_auto_refresh")
        with col_interval:
            refresh_seconds = st.number_input(
                "새로고침 간격(초)",
                min_value=2,
                max_value=60,
                value=5,
                step=1,
                key="strix_refresh_seconds",
            )

        status_slot = st.empty()
        findings_slot = st.empty()

        status = None
        try:
            status = client.get_job_status(int(last_job_id))
            status_slot.json(status)
        except Exception as exc:
            status_slot.error(str(exc))

        try:
            findings = client.list_findings(job_id=int(last_job_id), limit=500, offset=0)
            findings_slot.dataframe(findings, use_container_width=True)
        except Exception as exc:
            findings_slot.error(str(exc))

        last_scan_type = st.session_state.get("strix_last_scan_type") or ("dynamic" if is_dynamic else "static")
        run_name = st.session_state.get("strix_last_run_name") or f"job-{last_job_id}-strix-{last_scan_type}"
        log_path = Path("storage") / "artifacts" / str(last_job_id) / "strix" / run_name / "stdout.log"

        st.subheader("7) 실행 로그")
        log_text = _read_log_tail(log_path)
        if log_text:
            parsed = _parse_live_status(log_text)
            if parsed.get("status_line"):
                st.info(parsed["status_line"])
            if parsed.get("target"):
                st.caption(f"Target: {parsed['target']}")
            if parsed.get("results_path"):
                st.caption(f"Results: {parsed['results_path']}")
            col1, col2, col3 = st.columns(3)
            col1.metric("Vulnerabilities", parsed.get("vulnerabilities", "-"))
            col2.metric("Model", parsed.get("model", "-"))
            agents = parsed.get("agents", "-")
            tools = parsed.get("tools", "-")
            col3.metric("Agents / Tools", f"{agents} / {tools}")

            col4, col5, col6 = st.columns(3)
            col4.metric("Input", parsed.get("input", "-"))
            col5.metric("Cached", parsed.get("cached", "-"))
            col6.metric("Output / Cost", f"{parsed.get('output', '-')} / {parsed.get('cost', '-')}")

            with st.expander("원본 로그 보기"):
                init_block = _extract_latest_block(log_text, "STRIX PENETRATION TEST INITIATED")
                live_block = _extract_latest_block(log_text, "Live Penetration Test Status")
                if init_block:
                    st.code(init_block)
                if live_block:
                    st.code(live_block)
                if not init_block and not live_block:
                    st.text(log_text[-4000:])
        else:
            st.info(f"stdout.log가 아직 생성되지 않았습니다: {log_path}")

        if status and status.get("status") in {"COMPLETED", "FAILED"}:
            st.subheader("8) 보고서")
            col_create, col_view = st.columns(2)
            with col_create:
                if st.button("보고서 생성(json)", key="strix_create_report"):
                    try:
                        created = client.create_report(int(last_job_id), "json")
                        st.success(f"Report 생성 완료: id={created.get('id')}")
                        st.session_state["strix_report_id"] = created.get("id")
                        st.cache_data.clear()
                    except Exception as exc:
                        st.error(str(exc))

            reports = []
            try:
                reports = _load_reports(client, int(last_job_id))
            except Exception as exc:
                st.error(str(exc))

            report_map: Dict[str, Dict[str, Any]] = {}
            labels = []
            for report in sorted(reports, key=lambda item: item.get("id", 0), reverse=True):
                label = _format_report_label(report)
                labels.append(label)
                report_map[label] = report

            selected_label = None
            if labels:
                selected_label = st.selectbox("Report 선택", options=labels, key="strix_report_select")
            else:
                st.info("생성된 보고서가 없습니다.")

            with col_view:
                if st.button("보고서 보기", key="strix_view_report"):
                    report = report_map.get(selected_label) if selected_label else None
                    report_id = st.session_state.get("strix_report_id") or (report or {}).get("id")
                    if not report_id:
                        st.warning("보고서가 선택되지 않았습니다.")
                        return
                    report_format = str((report or {}).get("format", "JSON")).lower()
                    if report_format != "json":
                        st.warning("JSON 형식의 보고서만 테이블로 표시할 수 있습니다.")
                        return
                    try:
                        payload = fetch_report_json(api_base_url, int(report_id))
                        render_report(payload)
                    except Exception as exc:
                        st.error(str(exc))

        if auto_refresh and status and status.get("status") in {"PENDING", "RUNNING"}:
            import time

            time.sleep(int(refresh_seconds))
            _rerun()


if __name__ == "__main__":
    main()
