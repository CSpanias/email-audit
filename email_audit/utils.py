"""
General utility functions used throughout Email-Audit.
"""

import subprocess


def run_command(command):
    """
    Execute an external command and return its output.

    Return the exit status and combined output, including on failure.
    """

    completed = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", check=False,
    )
    return completed.returncode, completed.stdout.strip()