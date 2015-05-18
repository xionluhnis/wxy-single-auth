# wxy-single-auth
Plugin for single-user authentication within wxy

## System

* `url?login` triggers authentication
* `url?logout` logs you out

When logged in, the following parameters are available in the templates:

* `is_logged` - set to true
* `login` - set to the user login

## Configuration

```php
$config['auth-user']   = 'username';
$config['auth-realm']  = 'digest_realm_name';
$config['auth-ha1']    = md5("{$user}:{$realm}:{$pass}");
// optional:
$config['auth-login']  = 'required_login_value';    // ?login=required_login_value
$config['auth-logout'] = 'required_logout_value';   // ?logout=required_logout_value
```

## License

MIT
