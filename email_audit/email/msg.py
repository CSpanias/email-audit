"""
MSG to EML conversion utilities.
"""

import os
import subprocess
import tempfile

from shutil import which


# ---------------------------------------------------------------------------
# MSG Conversion
# ---------------------------------------------------------------------------
def convert_msg_to_eml(msg_file):
    """
    Convert a Microsoft Outlook MSG file into EML format.

    The conversion uses the external 'msgconvert' utility and
    returns the path of a temporary EML file suitable for
    subsequent parsing.
    """

    if not which("msgconvert"):
        raise RuntimeError("msgconvert is not installed. "
        "Install libemail-outlook-message-perl.")

    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
        eml_path = temp_file.name

    result = subprocess.run(
        ["msgconvert", "--outfile", eml_path, msg_file], 
        capture_output=True, 
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError("Failed to convert MSG file using msgconvert.")
    return eml_path