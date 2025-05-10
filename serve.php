<?php
/**
 * Serves files from a secured directory after Moodle authentication.
 *
 * This script expects a 'file' GET parameter, which is a relative path
 * to the file within the configured base media directory.
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
    throw new moodle_exception('config_error_basepath', 'local_securefiles'); // Shows a Moodle error page.
}

// Ensure the base path ends with a directory separator.
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// Require the user to be logged in.
require_login();

// Get the requested relative file path from the 'file' GET parameter.
$relative_file_path = required_param('file', PARAM_PATH);

// --- Security Checks ---

// 1. Disallow any '..' components in the path to prevent directory traversal.
if (strpos($relative_file_path, '..') !== false) {
   throw new moodle_exception('invalidpath', 'local_securefiles');
}

// 2. Construct the full, absolute path to the requested file.
$full_file_path = $base_media_path . $relative_file_path;

// 3. Normalize the path using realpath() and verify it's within the base directory.
$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);

// Check if the base path itself is valid.
if ($real_base_path === false) {
    error_log('Moodle local_securefiles: Configured base_path "' . $base_media_path . '" (resolved to: ' . $real_base_path . ') is invalid or not accessible.');
   throw new moodle_exception('config_error_basepath', 'local_securefiles');
   
}

// Check if the resolved file path is valid and starts with the resolved base path.
if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    error_log('Moodle local_securefiles: File access denied or not found. Requested: "'.$full_file_path.'", Resolved: "'.$real_file_path.'", Base: "'.$real_base_path.'"');
    throw new moodle_exception('filenotfound', 'local_securefiles');
}

// 4. Check if the path points to a file (not a directory) and is readable.
if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    error_log('Moodle local_securefiles: File not readable or is a directory. Path: "'.$real_file_path.'"');
    throw new moodle_exception('filenotfound', 'local_securefiles');
}

// --- Serve the File ---

// Get the filename for the Content-Disposition header.
$filename = basename($real_file_path);

// Determine the file extension.
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));

// Determine the MIME type of the file.
$mimetype = null;
if (function_exists('mime_content_type')) {
    $mimetype = mime_content_type($real_file_path);
    // Sometimes mime_content_type can return 'text/plain' for JS/CSS if server config is minimal.
    // We will override it with more specific types based on extension if needed.
    if (($extension === 'js' && $mimetype === 'text/plain') ||
        ($extension === 'css' && $mimetype === 'text/plain') ||
        ($extension === 'xml' && $mimetype === 'text/plain')) { // XML can also be text/xml or application/xml
        $mimetype = null; // Force fallback to extension-based switch
    }
}

// Fallback for MIME type if mime_content_type is not available or fails,
// or if we forced a fallback for common web types.
if (!$mimetype) {
    switch ($extension) {
        case 'pdf': $mimetype = 'application/pdf'; break;
        case 'txt': $mimetype = 'text/plain'; break;
        case 'html': case 'htm': $mimetype = 'text/html'; break;
        case 'css': $mimetype = 'text/css'; break;
        case 'js': $mimetype = 'application/javascript'; break; // Official MIME type for JavaScript
        case 'json': $mimetype = 'application/json'; break;
        case 'xml': $mimetype = 'application/xml'; break; // Or text/xml
        case 'jpg': case 'jpeg': $mimetype = 'image/jpeg'; break;
        case 'png': $mimetype = 'image/png'; break;
        case 'gif': $mimetype = 'image/gif'; break;
        case 'svg': $mimetype = 'image/svg+xml'; break;
        case 'mp3': $mimetype = 'audio/mpeg'; break;
        case 'mp4': $mimetype = 'video/mp4'; break;
        case 'webm': $mimetype = 'video/webm'; break;
        case 'ogg': $mimetype = 'application/ogg'; break; // Can be audio/ogg or video/ogg
        case 'zip': $mimetype = 'application/zip'; break;
        case 'doc': $mimetype = 'application/msword'; break;
        case 'docx': $mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'; break;
        case 'xls': $mimetype = 'application/vnd.ms-excel'; break;
        case 'xlsx': $mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'; break;
        case 'ppt': $mimetype = 'application/vnd.ms-powerpoint'; break;
        case 'pptx': $mimetype = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'; break;
        // Add more common SCORM/web types as needed.
        default: $mimetype = 'application/octet-stream'; // Generic binary type.
    }
}

// Clean any existing output buffers.
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Set HTTP headers for the file download/display.
header('Content-Type: ' . $mimetype);
header('Content-Length: ' . filesize($real_file_path));

// Content-Disposition: 'inline' tries to display in browser.
// 'attachment' forces download.
$disposition = 'inline';
// Force download for types that are typically not displayed inline or for safety.
if ($mimetype === 'application/octet-stream' || $extension === 'zip' || $extension === 'doc' || $extension === 'docx' || $extension === 'xls' || $extension === 'xlsx' || $extension === 'ppt' || $extension === 'pptx') {
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"');

// Security headers
header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, must-revalidate');
header('Pragma: public');

// Output the file contents.
if (!readfile($real_file_path)) {
    error_log('Moodle local_securefiles: readfile() failed for path: "'.$real_file_path.'"');
}

exit;