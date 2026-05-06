import json
from playwright.sync_api import sync_playwright, expect

def run_verification():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Mock APIs for the dashboard
        def handle_route(route):
            url = route.request.url
            if "/api/v1/auth/realms" in url and url.endswith("/realms"):
                route.fulfill(status=200, body=json.dumps([
                    {"id": "00000000-0000-0000-0000-000000000000", "name": "master", "enabled": True}
                ]))
            elif "/api/v1/auth/account/security-status" in url:
                route.fulfill(status=200, body=json.dumps({
                    "totp_enabled": True,
                    "webauthn_enabled": True,
                    "active_sessions": 3
                }))
            elif "/api/v1/auth/account/passkeys" in url:
                route.fulfill(status=200, body=json.dumps([
                    {"id": "11111111-1111-1111-1111-111111111111", "name": "Yubikey 5C", "created_at": "2024-01-01T12:00:00Z"},
                    {"id": "22222222-2222-2222-2222-222222222222", "name": "TouchID", "created_at": "2024-02-15T09:30:00Z"}
                ]))
            elif "/api/v1/auth/login" in url:
                route.fulfill(status=200, body=json.dumps({
                    "access_token": "mock-token",
                    "expires_in": 3600
                }))
            else:
                route.continue_()

        page.route("**/*", handle_route)

        # 1. Setup localStorage to bypass login for faster verification
        page.goto("http://localhost:3000") # We'll serve it
        page.evaluate("""() => {
            localStorage.setItem('authenc_token', 'mock-token');
            localStorage.setItem('authenc_user', 'admin');
            localStorage.setItem('authenc_realm', 'master');
            localStorage.setItem('authenc_realm_id', '00000000-0000-0000-0000-000000000000');
        }""")
        page.reload()

        # 2. Navigate to My Account tab
        page.click("#tab-account")

        # 3. Wait for data to load
        expect(page.locator("#acc-totp-status")).to_have_text("Enabled")
        expect(page.locator("#acc-webauthn-status")).to_have_text("Enabled")
        expect(page.locator("#acc-sessions-count")).to_have_text("3")

        # 4. Check passkeys table
        expect(page.locator("#account-passkeys-body tr")).to_have_count(2)
        expect(page.locator("#account-passkeys-body")).to_contain_text("Yubikey 5C")
        expect(page.locator("#account-passkeys-body")).to_contain_text("TouchID")

        # 5. Take screenshot
        page.screenshot(path="verification/account_dashboard.png")
        print("Screenshot saved to verification/account_dashboard.png")

        browser.close()

if __name__ == "__main__":
    run_verification()
