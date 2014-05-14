<?php
/*
Plugin Name: Nology WP Logging
Plugin URI: http://www.nologyinteractive.com
Description: Write all login attempts to the auth.log.
Version: 1.1
Author: Joey Durham
Author URI: http://www.nologyinteractive.com/
License: GPL2
*/

if ( is_admin() ) {
  function nolo_plugin_get_version() {
    if ( ! function_exists( 'get_plugins' ) )
        require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
    $nolojd_plugin_data = get_plugin_data( __FILE__ );
    return $nolojd_plugin_data['Version'];
  }

  add_action('init', 'nolo_activate_auto_update');
  function nolo_activate_auto_update()
  {
      require_once ('includes/nolo-class-auto-update.php');
      $nolojd_plugin_current_version = nolo_plugin_get_version();
      $nolojd_plugin_remote_path = 'http://www.nologyinteractive.com/nolo-repo/?p='.basename(__FILE__, '.php');
      $nolojd_plugin_slug = plugin_basename(__FILE__);
      new nolojd_auto_update ($nolojd_plugin_current_version, $nolojd_plugin_remote_path, $nolojd_plugin_slug);
  }
}

// apache_request_headers() is not available for everyone so we use a function
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
        if (isset($headers["X-Forwarded-For"])) {
         $real_client_ip = $headers["X-Forwarded-For"];
        }
        if (isset($real_client_ip)) {
          $theip = $real_client_ip;
        } else {
          $theip = $_SERVER['REMOTE_ADDR'];
        }
        openlog('wordpress('.$_SERVER['HTTP_HOST'].')',LOG_NDELAY|LOG_PID,LOG_AUTH);
        syslog(LOG_INFO,"Accepted password for $user_login from {$theip}");
      },10,2);

// log the failed login to /var/log/auth.log
add_action( 'wp_login_failed', function($username) {
        $headers = apache_request_headers();
        if (isset($headers["X-Forwarded-For"])) {
         $real_client_ip = $headers["X-Forwarded-For"];
        }
        if (isset($real_client_ip)) {
          $theip = $real_client_ip;
        } else {
          $theip = $_SERVER['REMOTE_ADDR'];
        }
        openlog('wordpress('.$_SERVER['HTTP_HOST'].')',LOG_NDELAY|LOG_PID,LOG_AUTH);
        syslog(LOG_NOTICE,"Authentication failure for $username from {$theip}");
});
