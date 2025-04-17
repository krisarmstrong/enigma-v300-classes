import pytest
import subprocess
import sys

def test_cli_help():
    """Test CLI --help invocation."""
    result = subprocess.run(
        [sys.executable, "enigma_v300_classes.py", "--help"],
        capture_output=True,
        text=True
    )
    assert result.returncode == 0
    assert "Fluke option key calculator" in result.stdout