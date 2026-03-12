import os
import json
import time
import subprocess
from playwright.sync_api import sync_playwright

def test_groups_ui():
    # Start a simple HTTP server in the background serving the static folder
    print("Starting static HTTP server...")
    http_server = subprocess.Popen(["python3", "-m", "http.server", "8000", "--directory", "static"])
    time.sleep(2)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            page.on("console", lambda msg: print(f"Browser console: {msg.text}"))

            # Route API calls using the localhost URL
            page.route("**/api/v1/auth/login", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"access_token": "fake_token", "token_type": "Bearer", "expires_in": 3600})
            ))

            page.route("**/api/v1/auth/realms/*/users", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([
                    {"id": "user1", "username": "admin", "email": "admin@example.com", "enabled": True, "email_verified": True}
                ])
            ))

            page.route("**/api/v1/auth/realms/*/groups", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([
                    {"id": "group1", "name": "Admins", "path": "/Admins", "description": "Administrator group"}
                ]) if route.request.method == "GET" else json.dumps(
                    {"id": "group2", "name": "TestGroup", "path": "/TestGroup", "description": "Test group"}
                ) # POST/PUT mock
            ))

            page.route("**/api/v1/auth/realms/*/groups/*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"message": "Success"})
            ))

            page.add_init_script("localStorage.clear();")

            url = "http://localhost:8000/index.html"
            print(f"Loading {url}")
            page.goto(url)

            # 1. Login
            print("Logging in...")
            page.wait_for_selector("#username", state="visible")
            page.fill("#username", "admin")
            page.fill("#password", "password")
            page.click("button[type='submit']")

            # Wait for dashboard to show
            print("Waiting for dashboard...")
            page.wait_for_selector("#dashboard-view:not(.hidden)", state="visible")

            # 2. Navigate to Groups Tab
            print("Navigating to groups tab...")
            page.click("#tab-groups")
            page.wait_for_selector("#groups-section:not(.hidden)", state="visible")

            # Verify initial group fetch
            print("Verifying initial groups fetch...")
            page.wait_for_selector("#groups-body tr td:has-text('Admins')")

            # 3. Create Group
            print("Creating a group...")
            page.click("button:has-text('Create Group')")
            page.wait_for_selector("#edit-group-modal:not(.hidden)", state="visible")
            page.fill("#edit-group-name", "TestGroup")
            page.fill("#edit-group-description", "A test group")

            # Save group
            print("Saving group...")
            page.click("#edit-group-form button[type='submit']")

            # Wait for modal to hide
            page.wait_for_selector("#edit-group-modal.hidden", state="hidden")

            # 4. Save a screenshot for verification
            print("Saving screenshot...")
            page.screenshot(path="groups_ui.png", full_page=True)
            print("Groups UI screenshot saved to groups_ui.png")

            browser.close()
    finally:
        http_server.terminate()
        http_server.wait()

if __name__ == "__main__":
    test_groups_ui()