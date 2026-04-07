from playwright.sync_api import sync_playwright, expect
import time
import re

def verify_ui(page):
    page.goto("http://localhost:8000/")

    # Mock login API
    page.route("**/api/v1/auth/login", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"access_token": "mock-token"}'
    ))

    # Mock realms API
    page.route("**/api/v1/auth/realms", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='[{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "master", "enabled": true}]'
    ))

    # Login
    page.locator("#login-form #password").fill("admin")
    page.get_by_role("button", name="Sign In", exact=True).click()

    # Switch to Users tab
    page.get_by_role("button", name="Users").click()

    # Mock users API
    page.route(re.compile(r".*/api/v1/auth/realms/.*/users$"), lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='[{"id": "u1", "username": "testuser", "email": "test@example.com", "enabled": true, "email_verified": true, "totp_enabled": true, "organization_id": "org1"}]'
    ))

    # Mock specific user GET
    page.route(re.compile(r".*/api/v1/auth/realms/.*/users/u1$"), lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"id": "u1", "username": "testuser", "email": "test@example.com", "enabled": true, "email_verified": true, "totp_enabled": true, "organization_id": "org1"}'
    ))

    # Mock social accounts GET
    page.route(re.compile(r".*/api/v1/auth/realms/.*/users/u1/social$"), lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='[]'
    ))

    # Click refresh to trigger load
    page.get_by_role("button", name="Refresh List").click()

    # Wait for user row
    expect(page.get_by_text("testuser")).to_be_visible()

    # Open Edit modal
    page.get_by_role("button", name="Edit").first.click()

    # Wait for modal content to be visible
    expect(page.get_by_text("Multi-Factor Authentication")).to_be_visible()

    # Scroll the specific modal card
    page.locator("#edit-user-modal .card").evaluate("el => el.scrollTop = el.scrollHeight")

    # Take screenshot
    page.screenshot(path="verification/verification_final.png")

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Larger viewport to see more
        context = browser.new_context(viewport={'width': 1280, 'height': 1200})
        page = context.new_page()
        try:
            verify_ui(page)
        finally:
            browser.close()
