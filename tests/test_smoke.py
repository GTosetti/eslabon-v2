import yara

import eslabon


def test_version_and_yara():
    assert eslabon.__version__ == "0.1.0"
    assert yara.__version__.startswith("4.5")
