import asyncio
from playwright.async_api import async_playwright
import os
import subprocess
import time
import signal
import re

async def run_verification():
    # Start a simple HTTP server to serve static files
    print("Starting static file server...")
    http_server = subprocess.Popen(["python3", "-m", "http.server", "3001"], cwd="static")
    time.sleep(2)

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Mock API responses
        await page.route(re.compile(r".*/api/v1/auth/login"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"access_token": "mock-token", "message": "Login successful"}'
        ))

        await page.route(re.compile(r".*/api/v1/auth/realms"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='[{"id": "00000000-0000-0000-0000-000000000000", "name": "master", "enabled": true}]'
        ))

        await page.route(re.compile(r".*/api/v1/zero-trust/dashboard/security.*"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"active_sessions": 10, "trusted_devices": 5, "risky_sessions": 1, "compliance_rate": 0.9}'
        ))

        await page.route(re.compile(r".*/api/v1/admin/identity-providers.*"), lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='[]'
        ))

        print("Navigating to login page...")
        await page.goto("http://localhost:3001")

        # Perform login
        await page.fill("#password", "admin")
        await page.click("button[type='submit']")

        # Wait for dashboard
        print("Waiting for dashboard...")
        await page.wait_for_selector("#dashboard-view:not(.hidden)")

        # Check for Identity Providers tab
        print("Checking for Identity Providers tab...")
        providers_tab = await page.query_selector("#tab-providers")
        await providers_tab.click()

        # Click Create Provider
        print("Opening Create Provider modal...")
        await page.click("button:has-text('Create Provider')")
        await page.wait_for_selector("#edit-provider-modal:not(.hidden)")

        # Select LDAP type
        print("Selecting LDAP type...")
        await page.select_option("#edit-provider-type", "LDAP")

        # Check if wizard is visible
        is_wizard_visible = await page.is_visible("#ldap-wizard")
        print(f"LDAP Wizard visible: {is_wizard_visible}")

        is_json_hidden = not await page.is_visible("#provider-config-json-container")
        print(f"JSON container hidden: {is_json_hidden}")

        # Check defaults
        ldap_url = await page.input_value("#ldap-url")
        print(f"Default LDAP URL: {ldap_url}")

        # Take screenshot of the wizard
        os.makedirs("verification", exist_ok=True)
        await page.screenshot(path="verification/ldap_wizard.png")
        print("Screenshot saved to verification/ldap_wizard.png")

        await browser.close()

    http_server.terminate()

if __name__ == "__main__":
    asyncio.run(run_verification())
