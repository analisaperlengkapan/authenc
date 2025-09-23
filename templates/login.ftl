<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Authenc</title>
    <link rel="stylesheet" href="common/keycloak.css">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>Welcome to Authenc</h1>
            <form method="post" action="${url.loginAction}">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" value="${(login.username!'')}" autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password">
                </div>
                <#if message??>
                <div class="alert alert-${message.type}">${message.summary}</div>
                </#if>
                <button type="submit" class="btn btn-primary">Sign In</button>
            </form>
        </div>
    </div>
</body>
</html>
