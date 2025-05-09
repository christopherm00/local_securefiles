<?php
/**
 * Serves files from a secured directory after Moodle authentication.
 *
 * This script expects a 'file' GET parameter, which is a relative path
 * to the file within the configured base media directory.
 *
 * Example URL after mod_rewrite: https://my.newdomain.com/media/path/to/file.pdf
 * The mod_rewrite rule should pass 'path/to/file.pdf' as the 'file' parameter.
 *
 * @package   local_securefiles
 * @copyright 2025 Christopher Murad - Moodle Contractor
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// Bootstrap Moodle.
require(__DIR__ . '/../../config.php');

// Get the configured base path for media files from plugin settings.
$base_media_path_config = get_config('local_securefiles', 'base_path');

if (empty($base_media_path_config)) {
    error_log('Moodle local_securefiles: base_path setting is not configured.');
    throw new moodle_exception('config_error_basepath', 'local_securefiles');
}

$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

require_login();

$relative_file_path = required_param('file', PARAM_PATH);

// --- Security Checks ---
if (strpos($relative_file_path, '..') !== false) {
    throw new moodle_exception('invalidpath', 'local_securefiles');
}

$full_file_path = $base_media_path . $relative_file_path;

$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);

if ($real_base_path === false) {
    error_log('Moodle local_securefiles: Configured base_path "' . $base_media_path . '" (resolved to: ' . $real_base_path . ') is invalid or not accessible.');
    echo 'Moodle local_securefiles: Configured base_path "' . $base_media_path . '" (resolved to: ' . $real_base_path . ') is invalid or not accessible.';

    throw new moodle_exception('config_error_basepath', 'local_securefiles');
}

if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    error_log('Moodle local_securefiles: File access denied or not found. Requested: "'.$full_file_path.'", Resolved: "'.$real_file_path.'", Base: "'.$real_base_path.'"');
    throw new moodle_exception('filenotfound', 'local_securefiles');
}

if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    error_log('Moodle local_securefiles: File not readable or is a directory. Path: "'.$real_file_path.'"');
    throw new moodle_exception('filenotfound', 'local_securefiles');
}

// --- Serve the File ---

$filename = basename($real_file_path);

// **MODIFICATION START**: Define $extension early.
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
// **MODIFICATION END**

$mimetype = null;
if (function_exists('mime_content_type')) {
    $mimetype = mime_content_type($real_file_path);
}

if (!$mimetype) {
    // $extension is already defined above, so we can use it directly here.
    switch ($extension) {
        case 'pdf': $mimetype = 'application/pdf'; break;
        case 'txt': $mimetype = 'text/plain'; break;
        case 'html': $mimetype = 'text/html'; break;
        case 'jpg': case 'jpeg': $mimetype = 'image/jpeg'; break;
        case 'png': $mimetype = 'image/png'; break;
        case 'gif': $mimetype = 'image/gif'; break;
        case 'zip': $mimetype = 'application/zip'; break;
        case 'doc': $mimetype = 'application/msword'; break;
        case 'docx': $mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'; break;
        case 'xls': $mimetype = 'application/vnd.ms-excel'; break;
        case 'xlsx': $mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'; break;
        case 'ppt': $mimetype = 'application/vnd.ms-powerpoint'; break;
        case 'pptx': $mimetype = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'; break;
        default: $mimetype = 'application/octet-stream';
    }
}

// Clean any existing output buffers. This is important to prevent interference
// with file serving, especially if any stray output (like the previous warning) occurred.
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Set HTTP headers for the file download/display.
header('Content-Type: ' . $mimetype);
header('Content-Length: ' . filesize($real_file_path));

$disposition = 'inline';
// Now $extension is guaranteed to be defined here.
if ($mimetype === 'application/octet-stream' || $extension === 'zip') {
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"');

header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, must-revalidate');
header('Pragma: public'); // HTTP 1.0 compatibility.

if (!readfile($real_file_path)) {
    error_log('Moodle local_securefiles: readfile() failed for path: "'.$real_file_path.'"');
    // Headers are already sent, so a Moodle error page can't be shown here.
    // The browser will likely show a connection error or incomplete file.
}

exit;
