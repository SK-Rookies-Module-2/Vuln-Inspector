"""원격 진단 실행 페이지."""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Tuple

import streamlit as st

from lib.api_client import APIClient
from lib.schemas import parse_json


@st.cache_data(ttl=5)
def _load_targets(base_url: str) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_targets(limit=1000, offset=0)


@st.cache_data(ttl=5)
def _load_remote_plugins(base_url: str) -> List[Dict[str, Any]]:
    client = APIClient(base_url)
    return client.list_plugins(plugin_type="remote")


def _format_target_label(target: Dict[str, Any]) -> str:
    info = target.get("connection_info") or {}
    host = info.get("host") or info.get("ip") or ""
    name = target.get("name") or f"target-{target.get('id')}"
    return f"{name} (id={target.get('id')}, {host})"


def _validate_overrides(overrides: Dict[str, Any]) -> Tuple[bool, str]:
    for key, value in overrides.items():
        if not isinstance(value, dict):
            return False, f"Override for '{key}' must be a JSON object"
    return True, ""


def _rerun() -> None:
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


def main() -> None:
    st.header("원격 진단(Remote)")

    api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
    st.caption(f"API_BASE_URL = {api_base_url}")

    client = APIClient(api_base_url)

    try:
        targets = _load_targets(api_base_url)
        plugins = _load_remote_plugins(api_base_url)
    except Exception as exc:
        st.error(str(exc))
        return

    server_targets = [t for t in targets if t.get("type") == "SERVER"]

    st.subheader("1) 대상 선택")
    target_labels = { _format_target_label(t): t for t in server_targets }
    selected_label = st.selectbox(
        "SERVER 대상",
        options=list(target_labels.keys()) or ["(등록된 SERVER 대상이 없습니다)"]
    )
    selected_target = target_labels.get(selected_label)

    with st.expander("새 대상 등록"):
        with st.form("create_remote_target"):
            name = st.text_input("대상 이름", value="remote-target")
            host = st.text_input("host/ip", value="127.0.0.1")
            port = st.number_input("port", min_value=1, max_value=65535, value=22, step=1)
            username = st.text_input("username", value="root")
            password = st.text_input("password (선택)", type="password")
            key_path = st.text_input("key_path (선택)", value="")
            description = st.text_input("설명(선택)", value="")
            submitted = st.form_submit_button("대상 등록")

        if submitted:
            payload = {
                "name": name,
                "type": "SERVER",
                "connection_info": {"host": host, "port": int(port)},
                "credentials": {
                    "username": username,
                    "password": password or None,
                    "key_path": key_path or None,
                },
                "description": description or None,
            }
            try:
                result = client.create_target(payload)
                st.success(f"대상 등록 완료: id={result.get('id')}")
                st.cache_data.clear()
            except Exception as exc:
                st.error(str(exc))

    st.subheader("2) 플러그인 선택")
    if "remote_selected_plugins" not in st.session_state:
        st.session_state["remote_selected_plugins"] = []

    plugin_options = []
    plugin_map = {}
    for plugin in sorted(plugins, key=lambda item: item.get("id", "")):
        label = f"{plugin.get('id')} | {plugin.get('name')}"
        plugin_options.append(label)
        plugin_map[label] = plugin.get("id")

    col1, col2 = st.columns(2)
    if col1.button("모두 선택"):
        st.session_state["remote_selected_plugins"] = plugin_options
    if col2.button("선택 해제"):
        st.session_state["remote_selected_plugins"] = []

    selected_labels = st.multiselect(
        "Remote 플러그인",
        options=plugin_options,
        default=st.session_state["remote_selected_plugins"],
        key="remote_selected_plugins",
    )
    selected_plugin_ids = [plugin_map[label] for label in selected_labels]
    st.caption(f"선택된 플러그인: {len(selected_plugin_ids)}개")

    st.subheader("3) 공통 설정")
    os_type = st.selectbox("os_type", ["linux", "solaris", "aix", "hpux"], index=0)
    use_sudo = st.checkbox("use_sudo", value=False)
    sudo_user = st.text_input("sudo_user (옵션)", value="")
    allow_local_fallback = st.checkbox("allow_local_fallback", value=False)
    max_results = st.number_input("max_results (옵션)", min_value=1, max_value=1000, value=200, step=10)

    st.subheader("4) 플러그인별 오버라이드(선택)")
    overrides_text = st.text_area(
        "scan_config overrides (JSON)",
        value=json.dumps({}, ensure_ascii=False, indent=2),
        height=160,
    )

    overrides: Dict[str, Any] = {}
    override_error = ""
    try:
        overrides = parse_json(overrides_text)
        ok, message = _validate_overrides(overrides)
        if not ok:
            override_error = message
    except Exception as exc:
        override_error = str(exc)

    if override_error:
        st.error(f"오버라이드 오류: {override_error}")

    st.subheader("5) 실행")
    if st.button("원격 진단 실행"):
        if override_error:
            st.error("오버라이드 오류를 먼저 수정하세요.")
            return
        if not selected_target:
            st.error("SERVER 대상이 필요합니다.")
            return
        if not selected_plugin_ids:
            st.error("하나 이상의 Remote 플러그인을 선택하세요.")
            return

        common_config: Dict[str, Any] = {"os_type": os_type}
        if use_sudo:
            common_config["use_sudo"] = True
        if sudo_user:
            common_config["sudo_user"] = sudo_user
        if allow_local_fallback:
            common_config["allow_local_fallback"] = True
        if max_results:
            common_config["max_results"] = int(max_results)

        scan_config: Dict[str, Dict[str, Any]] = {}
        for plugin_id in selected_plugin_ids:
            merged = dict(common_config)
            merged.update(overrides.get(plugin_id, {}))
            scan_config[plugin_id] = merged

        payload = {
            "target_id": int(selected_target.get("id")),
            "scan_scope": selected_plugin_ids,
            "scan_config": scan_config,
            "run_now": True,
        }

        try:
            result = client.create_job(payload)
            st.success(f"Job 생성 완료: id={result.get('id')}")
            st.session_state["remote_last_job_id"] = result.get("id")
            st.json(result)
        except Exception as exc:
            st.error(str(exc))

    last_job_id = st.session_state.get("remote_last_job_id")
    if last_job_id:
        st.subheader("6) 진행 상태/결과")
        st.caption(f"현재 Job ID: {last_job_id}")

        col_refresh, col_interval = st.columns(2)
        with col_refresh:
            auto_refresh = st.checkbox("자동 새로고침", value=True, key="remote_auto_refresh")
        with col_interval:
            refresh_seconds = st.number_input(
                "새로고침 간격(초)",
                min_value=2,
                max_value=30,
                value=5,
                step=1,
                key="remote_refresh_seconds",
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

        if auto_refresh and status and status.get("status") in {"PENDING", "RUNNING"}:
            time.sleep(int(refresh_seconds))
            _rerun()


if __name__ == "__main__":
    main()
