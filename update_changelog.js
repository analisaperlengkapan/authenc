const fs = require('fs');
let code = fs.readFileSync('CHANGELOG.md', 'utf8');
const search = '- **[BREAKING] API Path Parameters:**';
const insert = '- **[BREAKING] Security Authorization:** The `GET /api/v1/auth/realms/{realm}/roles` and `GET /api/v1/auth/realms/{realm}/permissions` endpoints now strictly require an `Authorization: Bearer <token>` header (`AuthBearer`). They were previously inadvertently unauthenticated. Integrations enumerating these endpoints anonymously will now receive a `401 Unauthorized`.\n';
code = code.replace(search, insert + search);
fs.writeFileSync('CHANGELOG.md', code);
