const fs = require('fs');
let code = fs.readFileSync('CHANGELOG.md', 'utf8');
const search = '### Changed';
const insert = '\n- **[BREAKING] API Path Parameters:** All Realm-scoped API endpoints (Users, Groups, Roles, Permissions, Clients, User Roles) now strictly enforce that the `{realm}` path parameter is a valid UUID (`Uuid::parse_str`), rather than a realm name string. This guarantees exact and unambiguous multi-tenant data isolation. API consumers previously passing realm names (e.g., `master`) in the URL path will now receive a `400 Bad Request` and must migrate to passing the exact Realm UUID.';
code = code.replace(search, search + insert);
fs.writeFileSync('CHANGELOG.md', code);
