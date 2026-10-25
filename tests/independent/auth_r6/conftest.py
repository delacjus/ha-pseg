"""Independent auth_r6 probes: marked via module-level pytestmark in each test file.

No collection hooks here: a conftest pytest_collection_modifyitems hook
receives every item in the session, not just this directory's.
"""
