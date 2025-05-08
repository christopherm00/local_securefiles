<?php
/**
 * Settings for the local_securefiles plugin.
 *
 * @package   local_securefiles
 * @copyright 2025 Christopher Murad - Moodle Contractor
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

// Ensure this only runs if the user has permission to manage site configuration.
// This is typically handled by Moodle's admin pages loading mechanism.
if (is_siteadmin()) { // More robust check than $hassiteconfig in this context.
    // Create a new admin settings page.
    // 'local_securefiles_settings' is a unique name for the settings page.
    // new lang_string('settings_title', 'local_securefiles') uses the lang string for the page title.
    $settings = new admin_settingpage('local_securefiles_settings', new lang_string('settings_title', 'local_securefiles'));

    // Add the settings page to the "Local plugins" section in site administration.
    $ADMIN->add('localplugins', $settings);

    // Setting for the base path of the media files.
    // 'local_securefiles/base_path' is the unique name for this setting.
    // It will be stored in the mdl_config_plugins table.
    $name = 'local_securefiles/base_path';
    $title = new lang_string('base_path', 'local_securefiles');
    $description = new lang_string('base_path_desc', 'local_securefiles');
    $description .= '<br>' . new lang_string('base_path_warning', 'local_securefiles'); // Add warning
    $default = '/mnt/nfs/media/'; // Sensible default, but admin MUST verify.

    // admin_setting_configtext creates a text input field for the setting.
    // PARAM_RAW allows most characters, suitable for paths. Admins are trusted.
    // Consider PARAM_SAFEDIR if you want Moodle to do some basic path validation,
    // but for absolute paths outside Moodle data, PARAM_RAW or PARAM_TEXT is common.
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_TEXT);
    $settings->add($setting);
}

