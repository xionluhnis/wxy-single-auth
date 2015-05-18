<?php

include_once ROOT_DIR . '/files.php';

/**
 * Plugin that enables login/logout for a single user
 *
 * @author Alexandre Kaspar
 */
class Single_User_Auth {

    // for authentication
    private $user;
    private $realm;
    private $digest_ha1;
    private $nonce;
    // for route checking
    private $login_value;
    private $logout_value;

    public function __construct() {
    }

    public function config_loaded($config){
        // user
        if(array_key_exists('auth-user', $config))
            $this->user = $config['auth-user'];
        else
            $this->user = FALSE;
        // realm
        if(array_key_exists('auth-realm', $config))
            $this->realm = $config['auth-realm'];
        else
            $this->realm = "wxy";
        // HA1 part of digest
        // @see http://en.wikipedia.org/wiki/Digest_access_authentication
        if(array_key_exists('auth-ha1', $config))
            $this->digest_ha1 = $config['auth-ha1'];
        else
            $this->digest_ha1 = '';

        // login and logout required values
        if(array_key_exists('auth-login-value', $config))
            $this->login_value = $config['auth-login-value'];
        else
            $this->login_value = FALSE;
        if(array_key_exists('auth-logout-value', $config))
            $this->logout_value = $config['auth-logout-value'];
        else
            $this->logout_value = FALSE;
    }

    public function request_url(&$route){
        if(empty($this->digest_ha1))
            return;
        // we want a session to store logins
        session_start();

        if(isset($_SESSION['nonce']) && strlen($_SESSION['nonce']) > 0)
            $this->nonce = $_SESSION['nonce'];
        else
            $this->nonce = $_SESSION['nonce'] = uniqid();

        // potential logout
        if(isset($_GET['logout'])
            && ($_GET['logout'] == $this->logout_value || $this->logout_value === FALSE)
        ){
            $this->logout();
        }

        // are we authentified already?

        // potential login
        if(isset($_GET['login'])
            && ($_GET['login'] == $this->login_value || $this->login_value === FALSE)
        ){
            $this->login();
        }
    }

    public static function authenticate($realm, $nonce) {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Digest realm="' . $realm . '", qop="auth", nonce="' . $nonce . '", opaque="' . md5($realm) . '"');
        die('Unauthorized access');
    }

    private function login() {
        // @see http://evertpot.com/223/
        // @see http://php.net/manual/en/features.http-auth.php

        // 1. Get authentication digest
        $digest = $this->get_digest();

        // 2. Ask for authentication if no digest
        if(empty($digest)) {
            self::authenticate($this->realm, $this->nonce);
        }

        // 3. Read authentication digest
        if(!($data = $this->http_digest_parse($digest))){
            die('Wrong digest');
        }

        // 4. Check authentication digest
        $A1 = $this->digest_ha1;
        $A2 = self::gen_ha2($_SERVER['REQUEST_METHOD'], $data['uri']);
        $valid_response = self::gen_response($A1, /* $this->nonce /* */ $data['nonce'], $data['nc'], $data['cnonce'], 'auth', $A2);

        // XXX the server nonce is not used by the client? there's something fishy here...
        // Note: you'd expect that $this->nonce === $data['nonce'], but it is NOT true...
        $same = array(
            'username'  => $this->user,
 //            'nonce'     => $this->nonce,
            'qop'       => 'auth'
        );
        foreach($same as $key => $val){
            if($data[$key] != $val){
                die('Unauthorized for ' . $key . ' -> ' . $data[$key] . ' <> ' . $val . ' -> ' . md5($val));
            }
        }

        if($valid_response != $data['response']){
            echo "$valid_response <-> {$data['response']}\n";
            self::authenticate($this->realm, $this->nonce);
        } else {
            $_SESSION['user'] = $this->user;
        }
    }

    public function get_digest() {
        // mod_php
        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
            $digest = $_SERVER['PHP_AUTH_DIGEST'];
            // most other servers
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (strpos(strtolower($_SERVER['HTTP_AUTHORIZATION']),'digest')===0)
                $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
        }
        return $digest;
    }

    public static function gen_ha1($user, $realm, $pass) {
        return md5("{$user}:{$realm}:{$pass}");
    }
    public static function gen_ha2($method, $uri) {
        $str = "{$method}:{$uri}";
        return md5($str);
    }
    public static function gen_response($ha1, $nonce, $nc, $cnonce, $qop, $ha2) {
        $str = "{$ha1}:{$nonce}:{$nc}:{$cnonce}:{$qop}:{$ha2}";
        return md5($str);
    }

    public function http_digest_parse($digest) {
        // protect against missing data
        $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
        $data = array();

        preg_match_all('@(\w+)=(?:(?:")([^"]+)"|([^\s,$]+))@', $digest, $matches, PREG_SET_ORDER);
        foreach ($matches as $m) {
            $data[$m[1]] = $m[2] ? $m[2] : $m[3];
            unset($needed_parts[$m[1]]);
        }
        return $needed_parts ? false : $data;
    }

    private function logout() {
        $_SESSION['user']   = '';
        $_SESSION['nonce']  = '';
    }


    public function before_render(&$twig_vars, &$twig, &$template) {
        if(empty($this->digest_ha1))
            return;
        if(!isset($_SESSION['user']))
            return;
        $user = $_SESSION['user'];
        if($user == $this->user){
            $twig_vars['login'] = $user;
            $twig_vars['is_logged'] = true;
        }
    }

}

?>
