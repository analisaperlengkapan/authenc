import asyncio
import os
import re
import json
from playwright.async_api import async_playwright
import http.server
import socketserver
import threading

# Configuration
PORT = 8001
DIRECTORY = "static"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start_server():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

async def run_test():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Mock APIs
        realm_id = "00000000-0000-0000-0000-000000000000"

        # 1. Mock Login
        await page.route(re.compile(r".*/api/v1/auth/login"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"access_token": "mock-token"})
        ))

        # 2. Mock Realms
        await page.route(re.compile(r".*/api/v1/auth/realms$"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps([{"id": realm_id, "name": "master"}])
        ))

        # 3. Mock Identity Providers (List)
        ldap_provider = {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "corporate-ldap",
            "display_name": "Corporate Directory",
            "provider_type": "LDAP",
            "enabled": True,
            "config": {
                "server_url": "ldap://old-server:389",
                "base_dn": "dc=legacy,dc=com",
                "user_search_filter": "(uid={0})",
                "username_attribute": "uid",
                "email_attribute": "mail",
                "first_name_attribute": "givenName",
                "last_name_attribute": "sn",
                "group_attribute": "memberOf",
                "role_mappings": json.dumps({"OldGroup": "old-role"})
            }
        }

        await page.route(re.compile(r".*/api/v1/admin/identity-providers\?realm_id=.*"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps([ldap_provider])
        ))

        # 4. Mock Update Provider
        captured_payload = {}
        async def handle_update(route):
            nonlocal captured_payload
            captured_payload = route.request.post_data_json
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(ldap_provider))

        await page.route(re.compile(r".*/api/v1/admin/identity-providers/.*"), handle_update)

        # Start Navigation
        await page.goto(f"http://localhost:{PORT}/index.html")

        # Login
        await page.fill("#password", "admin")
        await page.click("button[type='submit']")
        await page.wait_for_selector("#dashboard-view:not(.hidden)")

        # Switch to Providers Tab
        await page.click("#tab-providers")
        await page.wait_for_selector("#providers-table")

        # Click Edit on LDAP Provider
        await page.click("#providers-body button:has-text('Edit')")
        await page.wait_for_selector("#edit-provider-modal:not(.hidden)")

        # Verify Wizard Fields are populated from existing config
        url_val = await page.input_value("#ldap-url")
        assert url_val == "ldap://old-server:389", f"Expected old server URL, got {url_val}"

        base_dn_val = await page.input_value("#ldap-base-dn")
        assert base_dn_val == "dc=legacy,dc=com"

        email_attr_val = await page.input_value("#ldap-email-attr")
        assert email_attr_val == "mail"

        # Change values
        await page.fill("#ldap-url", "ldap://new-server:389")
        await page.fill("#ldap-base-dn", "dc=modern,dc=com")

        # Add a new role mapping
        await page.click("text=+ Add Mapping")
        # Find the last mapping row
        mapping_rows = await page.query_selector_all(".ldap-mapping-row")
        new_row = mapping_rows[-1]
        inputs = await new_row.query_selector_all("input")
        await inputs[0].fill("NewLdapGroup")
        await inputs[1].fill("new-authenc-role")

        # Save
        await page.click("#edit-provider-form button[type='submit']")

        # Wait for modal to close (or check captured payload)
        await page.wait_for_timeout(1000)

        # Assertions on captured payload
        print("Captured payload:", json.dumps(captured_payload, indent=2))

        config = captured_payload.get("config", {})
        assert config.get("server_url") == "ldap://new-server:389"
        assert config.get("base_dn") == "dc=modern,dc=com"
        assert config.get("group_attribute") == "memberOf"
        assert config.get("email_attribute") == "mail"

        role_mappings_raw = config.get("role_mappings", "{}")
        role_mappings = json.loads(role_mappings_raw)
        assert role_mappings.get("OldGroup") == "old-role"
        assert role_mappings.get("NewLdapGroup") == "new-authenc-role"

        print("LDAP Wizard Flow Test PASSED")
        await browser.close()

if __name__ == "__main__":
    # Start server in a thread
    daemon = threading.Thread(target=start_server, daemon=True)
    daemon.start()

    # Wait for server to start
    import time
    time.sleep(2)

    asyncio.run(run_test())
