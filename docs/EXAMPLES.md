# Authence API Usage Examples

## Register User
```
POST /realms/myrealm/users
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "secret",
  "roles": ["admin"]
}
```

## Login
```
POST /login
{
  "username": "alice",
  "password": "secret"
}
```

## Create Role
```
POST /realms/myrealm/roles
{
  "name": "editor"
}
```

## Assign Role to User
```
POST /realms/myrealm/users/{user_id}/roles/editor
```

## Create Permission
```
POST /realms/myrealm/permissions
{
  "name": "edit_article",
  "description": "Edit articles"
}
```

## Assign Permission to Role
```
POST /realms/myrealm/roles/editor/permissions/edit_article
```

## Check User Permission (with JWT)
```
GET /realms/myrealm/permissions/check?permission=edit_article
Authorization: Bearer <token>
```

## Audit Log
```
POST /realms/myrealm/audit
{
  "actor": "alice",
  "action": "assign_role",
  "target": "bob",
  "realm": "",
  "details": "Assigned editor role"
}

GET /realms/myrealm/audit
```
