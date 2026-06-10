import dash

# Initialize a minimal Dash app so that dashboard page modules can call
# dash.register_page() during import without raising PageError.
# This module-level initialization runs during pytest collection, before
# any test file in this directory is imported.
_test_app = dash.Dash("prowler_test_app", use_pages=True, pages_folder="")
