import os
import re
import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    marker = REPOSITORY_ROOT / ".git"
    if not marker.is_file():
        return environment

    git_directory = marker.read_text(encoding="utf-8").strip().removeprefix("gitdir: ")
    if os.name != "nt":
        windows_path = re.fullmatch(r"([A-Za-z]):[\\/](.+)", git_directory)
        if windows_path:
            git_directory = (
                f"/mnt/{windows_path.group(1).lower()}/"
                f"{windows_path.group(2).replace(chr(92), '/')}"
            )

    git_path = Path(git_directory)
    environment["GIT_DIR"] = str(git_path)
    environment["GIT_COMMON_DIR"] = str(git_path.parent.parent)
    environment["GIT_WORK_TREE"] = str(REPOSITORY_ROOT)
    return environment


def _ignored_paths(paths: list[str]) -> set[str]:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin", "-v"],
        cwd=REPOSITORY_ROOT,
        env=_git_environment(),
        input="\n".join(paths) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode in {0, 1}, result.stderr
    return {line.split("\t", 1)[1] for line in result.stdout.splitlines()}


def test_local_evidence_and_generated_outputs_remain_ignored():
    expected_ignored = {
        "evidence/stream-session.txt",
        "evidence/capture_full.txt",
        "evidence/webinvestigation/session.json",
        "zeek/run-1/packet_filter.log",
        "zeek/run-1/weird.log",
        "suricata/run-1/eve.json",
        "suricata/run-1/stats.log",
        "suricata_homenet/run-1/alerts.json",
        "simulations/beaconing/client.log",
        "simulations/beaconing/server_keepalive.log",
        "simulations/beaconing/nmap.out",
        "simulations/beaconing/phases.log",
        "simulations/beaconing/www/index.html",
    }

    assert _ignored_paths(sorted(expected_ignored)) == expected_ignored


def test_source_and_intentional_configuration_examples_are_not_ignored():
    retained_paths = [
        "suricata/rules/local.rules",
        "config/suricata-file-store-disabled.example.yaml",
        "simulations/beaconing/smoke_client.py",
    ]

    assert _ignored_paths(retained_paths) == set()
