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

// --- DEBUG FLAG ---
// Set to true to enable verbose logging for all requests handled by this script.
// Logs will typically go to your web server's error log (e.g., Apache error_log).
$debugSecureFiles = true;
// --- END DEBUG FLAG ---

// Bootstrap Moodle.
require(__DIR__ . '/../../config.php');

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Script execution started for request: " . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));
}

// Get the configured base path for media files from plugin settings.
$base_media_path_config = get_config('local_securefiles', 'base_path');

if (empty($base_media_path_config)) {
    error_log('Moodle local_securefiles: CRITICAL - base_path setting is not configured.');
    print_error('config_error_basepath', 'local_securefiles');
}

// Ensure the base path ends with a directory separator.
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// Require the user to be logged in.
require_login();

// Get the requested relative file path from the 'file' GET parameter.
$relative_file_path = required_param('file', PARAM_PATH);

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Requested relative_file_path: '{$relative_file_path}'");
}

// --- SCORM Path Detection ---
$isScormPath = (stripos($relative_file_path, 'SCORM') !== false);
if ($debugSecureFiles && $isScormPath) {
    error_log("SecureFiles Debug: Path identified as SCORM-related.");
}


// --- Security Checks ---

// 1. Disallow any '..' components in the path to prevent directory traversal.
if (strpos($relative_file_path, '..') !== false) {
    if ($debugSecureFiles) {
        error_log("SecureFiles Debug: Directory traversal attempt blocked for path: '{$relative_file_path}'");
    }
    print_error('invalidpath', 'local_securefiles');
}

// 2. Construct the full, absolute path to the requested file.
$full_file_path = $base_media_path . $relative_file_path;
if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Constructed full_file_path: '{$full_file_path}'");
}

// 3. Normalize the path using realpath() and verify it's within the base directory.
$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: real_base_path: '{$real_base_path}', real_file_path: '{$real_file_path}'");
}

// Check if the base path itself is valid.
if ($real_base_path === false) {
    error_log('Moodle local_securefiles: CRITICAL - Configured base_path "' . $base_media_path . '" is invalid or not accessible by the web server.');
    print_error('config_error_basepath', 'local_securefiles');
}

// Check if the resolved file path is valid and starts with the resolved base path.
if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    error_log("Moodle local_securefiles: WARNING - File access denied or not found. Requested: '{$full_file_path}', Resolved: '{$real_file_path}', Base: '{$real_base_path}'");
    print_error('filenotfound', 'local_securefiles');
}

// 4. Check if the path points to a file (not a directory) and is readable.
if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    error_log("Moodle local_securefiles: WARNING - File not readable or is a directory. Path: '{$real_file_path}'");
    print_error('filenotfound', 'local_securefiles');
}

// --- Serve the File ---

// Get the filename for the Content-Disposition header.
$filename = basename($real_file_path);

// Determine the file extension.
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Determined extension: '{$extension}' for file: '{$filename}'");
}

// Determine the MIME type of the file.
$mimetype = null;

// Prioritize known extensions, especially for web/SCORM content.
switch ($extension) {
    // Web Content (Critical for SCORM & general web use)
    case 'html':
    case 'htm':
        $mimetype = 'text/html';
        break;
    case 'css':
        $mimetype = 'text/css';
        break;
    case 'js':
        $mimetype = 'application/javascript'; // Official & most robust for JS
        if ($debugSecureFiles) {
            error_log("SecureFiles Debug: Matched extension 'js', setting MIME type to 'application/javascript'");
        }
        break;
    case 'json':
        $mimetype = 'application/json';
        break;
    case 'xml':
        $mimetype = 'application/xml';
        break;

    // Images
    case 'jpg':
    case 'jpeg':
        $mimetype = 'image/jpeg';
        break;
    case 'png':
        $mimetype = 'image/png';
        break;
    case 'gif':
        $mimetype = 'image/gif';
        break;
    case 'svg':
        $mimetype = 'image/svg+xml';
        break;
    case 'ico':
        $mimetype = 'image/vnd.microsoft.icon';
        break;

    // Audio/Video (Common in SCORM)
    case 'mp3':
        $mimetype = 'audio/mpeg';
        break;
    case 'mp4':
        $mimetype = 'video/mp4';
        break;
    case 'webm':
        $mimetype = 'video/webm';
        break;
    case 'ogg':
        $mimetype = 'application/ogg';
        break;
    case 'ogv':
        $mimetype = 'video/ogg';
        break;
    case 'oga':
        $mimetype = 'audio/ogg';
        break;
    case 'wav':
        $mimetype = 'audio/wav';
        break;
    case 'flv':
        $mimetype = 'video/x-flv';
        break;
    case 'swf':
        $mimetype = 'application/x-shockwave-flash';
        break;

    // Fonts
    case 'woff':
        $mimetype = 'font/woff';
        break;
    case 'woff2':
        $mimetype = 'font/woff2';
        break;
    case 'ttf':
        $mimetype = 'font/ttf';
        break;
    case 'otf':
        $mimetype = 'font/otf';
        break;
    case 'eot':
        $mimetype = 'application/vnd.ms-fontobject';
        break;

    // Documents
    case 'pdf':
        $mimetype = 'application/pdf';
        break;
    case 'txt':
        $mimetype = 'text/plain';
        break;
    case 'doc':
        $mimetype = 'application/msword';
        break;
    case 'docx':
        $mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        break;
    case 'xls':
        $mimetype = 'application/vnd.ms-excel';
        break;
    case 'xlsx':
        $mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        break;
    case 'ppt':
        $mimetype = 'application/vnd.ms-powerpoint';
        break;
    case 'pptx':
        $mimetype = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        break;

    // Archives
    case 'zip':
        $mimetype = 'application/zip';
        break;

    default:
        if ($debugSecureFiles || $isScormPath) {
            error_log("SecureFiles Debug/SCORM Trace: MIME determination entering DEFAULT case for Path='{$relative_file_path}', Extension='{$extension}', RealPath='{$real_file_path}'");
        }
        if (function_exists('mime_content_type')) {
            $mimetypeattempt = mime_content_type($real_file_path);
            if ($debugSecureFiles || $isScormPath) {
                error_log("SecureFiles Debug/SCORM Trace: mime_content_type() for '{$real_file_path}' returned '{$mimetypeattempt}'");
            }
            if ($mimetypeattempt !== false && $mimetypeattempt !== 'application/octet-stream' && !empty($mimetypeattempt)) {
                $mimetype = $mimetypeattempt;
            }
        }
        if (empty($mimetype)) {
            $mimetype = 'application/octet-stream';
            if ($debugSecureFiles || $isScormPath) {
                error_log("SecureFiles Debug/SCORM Trace: MIME type for Path='{$relative_file_path}' ultimately falling back to application/octet-stream.");
            }
        }
        break;
}

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Final determined MIME type for Path='{$relative_file_path}', Extension='{$extension}' is '{$mimetype}'");
}

// Clean any existing output buffers.
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Set HTTP headers for the file download/display.
header('Content-Type: ' . $mimetype);
header('Content-Length: ' . filesize($real_file_path));

$disposition = 'inline';
$attachment_extensions = ['zip', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
if ($mimetype === 'application/octet-stream' || in_array($extension, $attachment_extensions)) {
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"');

header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, must-revalidate');
header('Pragma: public');

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Headers sent. Attempting to readfile: '{$real_file_path}'");
}

if (!readfile($real_file_path)) {
    error_log('Moodle local_securefiles: ERROR - readfile() failed for path: "' . $real_file_path . '"');
}

if ($debugSecureFiles) {
    error_log("SecureFiles Debug: Script execution finished for: '{$relative_file_path}'");
}
exit;
