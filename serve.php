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
// __DIR__ is the directory of the current file (local/securefiles).
// So, __DIR__ . '/../../config.php' points to MOODLE_ROOT/config.php.
require(__DIR__ . '/../../config.php');

// Get the configured base path for media files from plugin settings.
$base_media_path_config = get_config('local_securefiles', 'base_path');

if (empty($base_media_path_config)) {
    // Configuration is missing. Log an error and inform the user.
    // This should ideally be caught by an admin when setting up.
    error_log('Moodle local_securefiles: base_path setting is not configured.');
    print_error('config_error_basepath', 'local_securefiles'); // Shows a Moodle error page.
}

// Ensure the base path ends with a directory separator.
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// Require the user to be logged in.
// This function handles redirection to the login page if the user is not logged in.
// It also initializes user session, etc.
require_login();

// Get the requested relative file path from the 'file' GET parameter.
// PARAM_PATH is used for relative file paths. It undergoes some cleaning.
$relative_file_path = required_param('file', PARAM_PATH);

// --- Security Checks ---

// 1. Disallow any '..' components in the path to prevent directory traversal.
//    Even though realpath() below should handle this, an early check is good.
if (strpos($relative_file_path, '..') !== false) {
    print_error('invalidpath', 'local_securefiles');
}

// 2. Construct the full, absolute path to the requested file.
$full_file_path = $base_media_path . $relative_file_path;

// 3. Normalize the path using realpath() and verify it's within the base directory.
//    realpath() resolves all symbolic links, '.', '..' and returns the canonicalized absolute pathname.
//    This is a crucial security step.
$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);

// Check if the base path itself is valid.
if ($real_base_path === false) {
    // The configured base_media_path does not exist or is not accessible by the web server.
    error_log('Moodle local_securefiles: Configured base_path "' . $base_media_path . '" (resolved to: ' . $real_base_path . ') is invalid or not accessible.');
    print_error('config_error_basepath', 'local_securefiles');
}

// Check if the resolved file path is valid and starts with the resolved base path.
// This ensures the file is actually within the intended media directory.
if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    // File does not exist, or it's outside the allowed base directory (traversal attempt).
    // Log the attempt for security auditing if desired.
    // For the user, show a generic "file not found" error.
    error_log('Moodle local_securefiles: File access denied or not found. Requested: "'.$full_file_path.'", Resolved: "'.$real_file_path.'", Base: "'.$real_base_path.'"');
    print_error('filenotfound', 'local_securefiles');
}

// 4. Check if the path points to a file (not a directory) and is readable.
if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    error_log('Moodle local_securefiles: File not readable or is a directory. Path: "'.$real_file_path.'"');
    print_error('filenotfound', 'local_securefiles');
}

// --- Serve the File ---

// Get the filename for the Content-Disposition header.
$filename = basename($real_file_path);

// Determine the MIME type of the file.
$mimetype = null;
if (function_exists('mime_content_type')) {
    $mimetype = mime_content_type($real_file_path);
}

// Fallback for MIME type if mime_content_type is not available or fails.
if (!$mimetype) {
    $extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
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
        // Add more common types as needed.
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

// Content-Disposition: 'inline' tries to display in browser (PDFs, images).
// 'attachment' forces download. For PDFs, 'inline' is usually desired.
$disposition = 'inline';
if ($mimetype === 'application/octet-stream' || $extension === 'zip') { // Force download for unknown or zip
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"'); // rawurlencode for filename

// Security headers
header('X-Content-Type-Options: nosniff'); // Prevents MIME-sniffing attacks.
// Caching: For private files, it's often best to prevent caching or use ETag/Last-Modified.
// For simplicity, we'll set it to revalidate.
header('Cache-Control: private, must-revalidate');
header('Pragma: public'); // HTTP 1.0 compatibility for Cache-Control.

// Output the file contents.
// readfile() is efficient for sending entire files.
if (!readfile($real_file_path)) {
    // This should ideally not happen if previous checks passed.
    error_log('Moodle local_securefiles: readfile() failed for path: "'.$real_file_path.'"');
    // Avoid sending a Moodle error page here as headers are already sent.
    // The browser will likely show a connection error or empty response.
}

// Terminate script execution.
exit;

