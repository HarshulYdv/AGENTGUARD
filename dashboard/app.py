"""AGENTGUARD Streamlit Dashboard application entrypoint."""

import streamlit as st
from backend import __version__
from backend.core.config import get_settings


def main() -> None:
    """Render the primary AGENTGUARD dashboard layout."""
    settings = get_settings()

    st.set_page_config(
        page_title=f"{settings.app_name} Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title("🛡️ AGENTGUARD Control Panel")
    st.caption("Task-aware runtime security and reliability framework for autonomous AI agents")

    st.divider()

    st.subheader("System Status")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(label="Framework Version", value=f"v{__version__}")
    with col2:
        st.metric(label="Environment", value=settings.app_env.capitalize())
    with col3:
        st.metric(label="API Port", value=str(settings.port))
    with col4:
        st.metric(label="Log Level", value=settings.log_level)

    st.info(
        "Stage 01 Foundation is active. Security guardrails, agent orchestration, and evaluation "
        "modules will be accessible from this dashboard in subsequent stages.",
        icon="ℹ️",
    )


if __name__ == "__main__":
    main()

