<?php
/*
Plugin Name: ILAB Basic Auth
Plugin URI: http://interfacelab.com/basic-auth
Description: Enables/disables HTTP basic auth on a per host basis
Author: Jon Gilkison
Version: 0.1.0
Author URI: http://interfacelab.com
*/
class ILABAuth {
    private $hosts=[];

    public function __construct() {
        add_action('template_redirect', [$this, 'checkAuth'], 1);

        add_action('admin_menu', function() {
            add_options_page('Basic Auth', 'Basic Auth', 'manage_options', 'ilab-basic-auth', [$this, 'displaySettings']);
        });

        add_action('admin_init',function(){
            register_setting( 'ilab-basic-auth-group', 'ilab-basic-auth-hosts' );
            register_setting( 'ilab-basic-auth-group', 'ilab-basic-auth-message' );
            register_setting( 'ilab-basic-auth-group', 'ilab-basic-auth-error' );
        });

        $hostList = get_option('ilab-basic-auth-hosts');
        if ($hostList && !empty($hostList)) {
            $hosts = explode("\n", $hostList);
            foreach($hosts as $host)
                $this->hosts[] = trim($host);
        }
    }

    public function checkAuth() {
        if (count($this->hosts)>0) {
            if (!in_array($_SERVER['HTTP_HOST'],$this->hosts))
                return;
        }

        if (is_user_logged_in())
            return;

        nocache_headers();

        $usr = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';
        $pwd = isset($_SERVER['PHP_AUTH_PW'])   ? $_SERVER['PHP_AUTH_PW']   : '';
        if (empty($usr) && empty($pwd) && isset($_SERVER['HTTP_AUTHORIZATION']) && $_SERVER['HTTP_AUTHORIZATION']) {
            list($type, $auth) = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (strtolower($type) === 'basic') {
                list($usr, $pwd) = explode(':', base64_decode($auth));
            }
        }

        $is_authenticated = wp_authenticate($usr, $pwd);
        if (!is_wp_error($is_authenticated))
            return;

        $message = get_option('ilab-basic-auth-message','Please enter your username and password.');
        $error = get_option('ilab-basic-auth-error','You need to supply a username or password to view this site.');

        header('WWW-Authenticate: Basic realm="'.$message.'"');
        wp_die($error, 'Authorization Required', ['response' => 401]);
    }

    public function displaySettings() {
        ?>
        <div class="wrap">
            <h2>Basic Auth</h2>
            <form method="post" action="options.php">
                <?php settings_fields( 'ilab-basic-auth-group' ); ?>
                <?php do_settings_sections( 'ilab-basic-auth-group' ); ?>
                <h2>Settings</h2>
                <p>You can enable basic auth on a per host basis by specifying the exact domains in the Hosts settings.  This is useful if you want to enable basic auth for dev or staging, but not production.</p>
                <p>If you don't define any hosts, basic auth will be required on every domain.</p>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row" style="text-align:right">Hosts</th>
                        <td><textarea style="width:100%; max-width: 350px;" rows="8" name="ilab-basic-auth-hosts"><?php echo esc_attr( get_option('ilab-basic-auth-hosts') ); ?></textarea></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row" style="text-align:right">Authentication Message</th>
                        <td><input style="width:100%; max-width: 350px;" type="text" name="ilab-basic-auth-message" value="<?php echo esc_attr( get_option('ilab-basic-auth-message') ); ?>" /></td>
                    </tr>
                    <tr valign="top">
                        <th scope="row" style="text-align:right">Failure Message</th>
                        <td><input style="width:100%; max-width: 350px;" type="text" name="ilab-basic-auth-error" value="<?php echo esc_attr( get_option('ilab-basic-auth-error') ); ?>" /></td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

}

new ILABAuth();