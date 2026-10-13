"""
General utility functions used throughout Email-Audit.
"""

import subprocess


def run_command(command):
    """
    Execute an external command and return its output.

    Returns the command output as a stripped string. If the command
    exits with a non-zero status, the error is displayed and an
    empty string is returned.
    """

    try:
        return (
            subprocess
            .check_output(command, stderr=subprocess.STDOUT)
            .decode()
            .strip()
        )

    except subprocess.CalledProcessError as e:

        print(f"ERROR: {e.output.decode()}")
        return ""