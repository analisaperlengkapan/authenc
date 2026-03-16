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

            def realms_handler(route):
                if route.request.method == "GET":
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps([
                            {"id": "00000000-0000-0000-0000-000000000000", "name": "master", "description": "Master Realm", "enabled": True}
                        ])
                    )
                else:
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps(
                            {"id": "test-realm-id", "name": "TestRealm", "description": "Test realm", "enabled": True}
                        )
                    )

            page.route("**/api/v1/auth/realms", realms_handler)
            page.route("**/api/v1/auth/realms/*/status", lambda route: route.fulfill(status=200))
            page.route("**/api/v1/auth/realms/*", lambda route: route.fulfill(status=200))

            page.route("**/api/v1/auth/realms/*/users", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([
                    {"id": "user1", "username": "admin", "email": "admin@example.com", "enabled": True, "email_verified": True}
                ])
            ))

            page.route("**/api/v1/auth/realms/*/groups/*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"message": "Success"})
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

            page.route("**/api/v1/auth/realms/*/roles/*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"message": "Success"})
            ))

            def roles_handler(route):
                if route.request.method == "GET":
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps([
                            {"id": "role1", "name": "AdminRole", "description": "Administrator role"}
                        ])
                    )
                else:
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps(
                            {"id": "role2", "name": "TestRole", "description": "Test role"}
                        )
                    )

            page.route("**/api/v1/auth/realms/*/roles", roles_handler)

            page.route("**/api/v1/auth/realms/*/users/*/social", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([]) if route.request.method == "GET" else json.dumps(
                    {"provider": "github", "provider_user_id": "test_github_id", "linked_at": "2023-01-01T00:00:00Z", "updated_at": "2023-01-01T00:00:00Z"}
                )
            ))

            page.route("**/api/v1/auth/realms/*/clients/*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"message": "Success"})
            ))

            page.route("**/api/v1/auth/realms/*/clients", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps([
                    {"client_id": "client1", "name": "Main App", "enabled": True, "redirect_uris": ["https://app.com"]}
                ]) if route.request.method == "GET" else json.dumps(
                    {"client_id": "client2", "name": "Test Client", "enabled": True}
                ) # POST/PUT mock
            ))

            page.route("**/api/v1/auth/realms/*/audit*", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "total": 1,
                    "logs": [
                        {"timestamp": "2023-01-01T00:00:00Z", "event": "user_login", "user_id": "test_user", "status": "success", "detail": "User logged in successfully"}
                    ]
                })
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

            # 2. Navigate to Realms Tab
            print("Navigating to realms tab...")
            page.click("#tab-realms")
            page.wait_for_selector("#realms-section:not(.hidden)", state="visible")

            # Verify initial realm fetch
            print("Verifying initial realms fetch...")
            page.wait_for_selector("#realms-body tr td:has-text('master')")

            # Create Realm
            print("Creating a realm...")
            page.click("button:has-text('Create Realm')")
            page.wait_for_selector("#edit-realm-modal:not(.hidden)", state="visible")
            page.fill("#edit-realm-name", "TestRealm")
            page.fill("#edit-realm-description", "A test realm")

            # Save realm
            print("Saving realm...")
            page.click("#edit-realm-form button[type='submit']")

            # Wait for modal to hide
            page.wait_for_selector("#edit-realm-modal.hidden", state="hidden")

            # Save a screenshot for verification
            print("Saving realms screenshot...")
            page.screenshot(path="realms_ui.png", full_page=True)
            print("Realms UI screenshot saved to realms_ui.png")

            # 3. Navigate to Groups Tab
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

            # 5. Navigate to Roles Tab
            print("Navigating to roles tab...")
            page.click("#tab-roles")
            page.wait_for_selector("#roles-section:not(.hidden)", state="visible")

            # Verify initial role fetch
            print("Verifying initial roles fetch...")
            page.wait_for_selector("#roles-body tr td:has-text('AdminRole')")

            # Create Role
            print("Creating a role...")
            page.click("button:has-text('Create Role')")
            page.wait_for_selector("#edit-role-modal:not(.hidden)", state="visible")
            page.fill("#edit-role-name", "TestRole")
            page.fill("#edit-role-description", "A test role")

            # Save role
            print("Saving role...")
            page.click("#edit-role-form button[type='submit']")

            # Wait for modal to hide
            page.wait_for_selector("#edit-role-modal.hidden", state="hidden")

            # Save a screenshot for verification
            print("Saving roles screenshot...")
            page.screenshot(path="roles_ui.png", full_page=True)
            print("Roles UI screenshot saved to roles_ui.png")

            # 6. Navigate to Users Tab to test social linking
            print("Navigating to users tab...")
            page.click("#tab-users")
            page.wait_for_selector("#users-section:not(.hidden)", state="visible")

            print("Opening edit user modal...")
            page.click("#users-body button:has-text('Edit')")
            page.wait_for_selector("#edit-user-modal:not(.hidden)", state="visible")

            print("Clicking Link Account...")
            page.click("button:has-text('Link Account')")
            page.wait_for_selector("#link-social-account-modal:not(.hidden)", state="visible")

            print("Filling Link Account form...")
            page.select_option("#link-social-provider", "github")
            page.fill("#link-social-provider-user-id", "test_github_id")
            page.fill("#link-social-email", "github@example.com")

            print("Submitting Link Account form...")
            page.click("#link-social-account-form button[type='submit']")

            # Wait for modal to hide
            page.wait_for_selector("#link-social-account-modal.hidden", state="hidden")

            print("Saving screenshot of social linking UI...")
            page.screenshot(path="social_linking_ui.png", full_page=True)
            print("Social linking UI screenshot saved to social_linking_ui.png")

            # Close edit user modal
            page.click("#edit-user-modal .secondary")
            page.wait_for_selector("#edit-user-modal.hidden", state="hidden")

            # 6. Navigate to Clients Tab
            print("Navigating to clients tab...")
            page.click("#tab-clients")
            page.wait_for_selector("#clients-section:not(.hidden)", state="visible")

            # Verify initial client fetch
            print("Verifying initial clients fetch...")
            page.wait_for_selector("#clients-body tr td:has-text('Main App')")

            # 7. Create Client
            print("Creating a client...")
            page.click("button:has-text('Create Client')")
            page.wait_for_selector("#edit-client-modal:not(.hidden)", state="visible")
            page.fill("#edit-client-client-id", "test-client")
            page.fill("#edit-client-name", "Test Client")
            page.fill("#edit-client-secret", "supersecret")
            page.fill("#edit-client-redirect-uris", "http://localhost:3000/callback")

            # Save client
            print("Saving client...")
            page.click("#edit-client-form button[type='submit']")

            # Wait for modal to hide
            page.wait_for_selector("#edit-client-modal.hidden", state="hidden")

            # 8. Save a screenshot for verification
            print("Saving clients UI screenshot...")
            page.screenshot(path="clients_ui.png", full_page=True)
            print("Clients UI screenshot saved to clients_ui.png")

            # 9. Navigate to Audit Logs Tab
            print("Navigating to audit logs tab...")
            page.click("#tab-audit")
            page.wait_for_selector("#audit-section:not(.hidden)", state="visible")

            # Verify initial audit logs fetch
            print("Verifying initial audit logs fetch...")
            page.wait_for_selector("#audit-body tr td:has-text('user_login')")

            # Save a screenshot for verification
            print("Saving audit logs UI screenshot...")
            page.screenshot(path="audit_ui.png", full_page=True)
            print("Audit Logs UI screenshot saved to audit_ui.png")

            browser.close()
    finally:
        http_server.terminate()
        http_server.wait()

if __name__ == "__main__":
    test_groups_ui()