from pathlib import Path


def test_dockerfile_uses_mcp_server_not_legacy_agent():
    dockerfile = Path("Dockerfile").read_text()
    assert "mcp_server.py" in dockerfile
    assert "agents/defender_agent.py" not in dockerfile


def test_docker_compose_uses_real_config_path():
    compose = Path("docker-compose.yml").read_text()
    assert "./cybersec_lab_integration/config.yaml" in compose
    assert "./cybersec-lab-integration/config.yaml" not in compose


def test_demo_runner_does_not_call_archived_legacy_agent():
    demo = Path("demo/run_demo.sh").read_text()
    assert "agents/defender_agent.py" not in demo
