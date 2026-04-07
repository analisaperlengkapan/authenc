import os
import json
import time
import subprocess
from playwright.sync_api import sync_playwright

def test_ui_enhancements():
    # Start a simple HTTP server in the background serving the static folder
    print("Starting static HTTP server...")
    http_server = subprocess.Popen(["python3", "-m", "http.server", "8001", "--directory", "static"])
    time.sleep(2)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # Mock Login
            page.route("**/api/v1/auth/login", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"access_token": "fake_token"})
            ))

            # Mock Realms
            def realms_handler(route):
                if route.request.method == "GET":
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps([
                            {"id": "00000000-0000-0000-0000-000000000000", "name": "master", "enabled": True}
                        ])
                    )
                else:
                    route.fulfill(status=200, body=json.dumps({"id": "some-id", "name": "test"}))
            page.route("**/api/v1/auth/realms", realms_handler)

            # Mock User
            page.route("**/api/v1/auth/realms/*/users/*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "id": "user1",
                    "username": "testuser",
                    "email": "test@example.com",
                    "enabled": True,
                    "email_verified": True,
                    "totp_enabled": True,
                    "organization_id": "00000000-0000-0000-0000-000000000001",
                    "attributes": {"key": "value"}
                })
            ))

            page.route("**/api/v1/auth/realms/*/users", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([
                    {"id": "user1", "username": "testuser", "email": "test@example.com", "enabled": True, "email_verified": True}
                ])
            ))

            page.route("**/api/v1/auth/realms/*/users/*/social", lambda route: route.fulfill(status=200, body="[]"))

            page.add_init_script("localStorage.clear();")

            url = "http://localhost:8001/index.html"
            print(f"Loading {url}")
            page.goto(url)

            # Login
            page.fill("#username", "admin")
            page.fill("#password", "password")
            page.click("button[type='submit']")
            page.wait_for_selector("#dashboard-view:not(.hidden)")

            # Verify User Edit Enhancements
            print("Verifying User Edit enhancements...")
            page.click("#tab-users")
            page.wait_for_selector("#users-body button:has-text('Edit')")
            page.click("#users-body button:has-text('Edit')")
            page.wait_for_selector("#edit-user-modal:not(.hidden)")

            # Check new fields
            assert page.is_visible("#edit-org-id")
            assert page.is_visible("#edit-attributes")
            assert page.inner_text("#totp-status-text") == "Enabled"
            assert page.is_visible("#disable-totp-btn")

            print("User Edit enhancements verified.")
            page.screenshot(path="user_edit_enhanced.png")

            # Verify Realm Edit Enhancements
            print("Verifying Realm Edit enhancements...")
            page.click("#edit-user-modal .secondary") # Close modal
            page.click("#tab-realms")
            page.click("#realms-body button:has-text('Edit')")
            page.wait_for_selector("#edit-realm-modal:not(.hidden)")

            assert page.is_visible("#edit-realm-display-name")
            assert page.is_visible("#edit-realm-reg-allowed")
            assert page.is_visible("#edit-realm-verify-email")
            assert page.is_visible("#edit-realm-reset-pwd")

            print("Realm Edit enhancements verified.")
            page.screenshot(path="realm_edit_enhanced.png")

            browser.close()
    finally:
        http_server.terminate()
        http_server.wait()

if __name__ == "__main__":
    test_ui_enhancements()
