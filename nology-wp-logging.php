<?php
/*
Plugin Name: Nology WP Logging
Plugin URI: http://www.nologyinteractive.com
Description: Write all login attempts to the auth.log.
Version: 1.0
Author: Joey Durham
Author URI: http://www.nologyinteractive.com/
License: GPL2
*/

// apache_request_headers() is not available for everyone
if( !function_exists('apache_request_headers') ) {
  function apache_request_headers() {
    $arh = array();
    $rx_http = '/\AHTTP_/';
    foreach($_SERVER as $key => $val) {
      if( preg_match($rx_http, $key) ) {
        $arh_key = preg_replace($rx_http, '', $key);
        $rx_matches = array();
        $rx_matches = explode('_', $arh_key);
        if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
          foreach($rx_matches as $ak_key => $ak_val) $rx_matches[$ak_key] = ucfirst($ak_val);
          $arh_key = implode('-', $rx_matches);
        }
        $arh[$arh_key] = $val;
      }
    }
    return( $arh );
  }
}

// log the successful login to /var/log/auth.log
add_action( 'wp_login', function($user_login, $user) {
        $headers = apache_request_headers();
        $real_client_ip = $headers["X-Forwarded-For"];
        if ($real_client_ip == '') {
          $theip = $_SERVER['REMOTE_ADDR'];
        } else {
         $theip = $real_client_ip;
        }
        openlog('wordpress('.$_SERVER['HTTP_HOST'].')',LOG_NDELAY|LOG_PID,LOG_AUTH);
        syslog(LOG_INFO,"Accepted password for $user_login from {$theip}");
      },10,2);

// log the failed login to /var/log/auth.log
add_action( 'wp_login_failed', function($username) {
        $headers = apache_request_headers();
        $real_client_ip = $headers["X-Forwarded-For"];
        if ($real_client_ip == '') {
          $theip = $_SERVER['REMOTE_ADDR'];
        } else {
         $theip = $real_client_ip;
        }
        openlog('wordpress('.$_SERVER['HTTP_HOST'].')',LOG_NDELAY|LOG_PID,LOG_AUTH);
        syslog(LOG_NOTICE,"Authentication failure for $username from {$theip}");
});
