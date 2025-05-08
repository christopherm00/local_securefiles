<?php
/**
 * English language strings for the local_securefiles plugin.
 *
 * @package   local_securefiles
 * @copyright 2025 Christopher Murad - Moodle Contractor
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = 'Secure Files Access';
$string['filenotfound'] = 'The requested file could not be found, may not exist, or you do not have permission to access it.';
$string['accessdenied'] = 'Access denied. You must be logged in to view this file.';
$string['invalidpath'] = 'The requested file path is invalid.';
$string['config_error_basepath'] = 'Secure Files Access: The configured base media path is invalid or not accessible. Please check plugin settings.';

// Settings strings
$string['settings_title'] = 'Secure Files Access Settings';
$string['base_path'] = 'Base Media Path';
$string['base_path_desc'] = 'The absolute server path to the root directory where media files are stored (e.g., /mnt/nfs/media/). This directory itself should NOT be web accessible directly.';
$string['base_path_warning'] = 'Warning: Ensure this path is correct and the web server process has read access to this directory and its contents.';


