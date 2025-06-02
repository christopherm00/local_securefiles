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
    print_error('config_error_basepath', 'local_securefiles'); // Shows a Moodle error page.
}

// Ensure the base path ends with a directory separator.
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// Require the user to be logged in.
require_login();

// Get the requested relative file path from the 'file' GET parameter.
$relative_file_path = required_param('file', PARAM_PATH);

// --- SCORM Path Detection ---
// Check if "SCORM" or "scorm" is in the path (case-insensitive)
// This flag can be used for conditional logging or specific handling if needed.
$isScormPath = (stripos($relative_file_path, 'SCORM') !== false);

// --- Security Checks ---

// 1. Disallow any '..' components in the path to prevent directory traversal.
if (strpos($relative_file_path, '..') !== false) {
    print_error('invalidpath', 'local_securefiles');
}

// 2. Construct the full, absolute path to the requested file.
$full_file_path = $base_media_path . $relative_file_path;

// 3. Normalize the path using realpath() and verify it's within the base directory.
$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);

// Check if the base path itself is valid.
if ($real_base_path === false) {
    error_log('Moodle local_securefiles: Configured base_path "' . $base_media_path . '" (resolved to: ' . $real_base_path . ') is invalid or not accessible.');
    print_error('config_error_basepath', 'local_securefiles');
}

// Check if the resolved file path is valid and starts with the resolved base path.
if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    error_log('Moodle local_securefiles: File access denied or not found. Requested: "' . $full_file_path . '", Resolved: "' . $real_file_path . '", Base: "' . $real_base_path . '"');
    print_error('filenotfound', 'local_securefiles');
}

// 4. Check if the path points to a file (not a directory) and is readable.
if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    error_log('Moodle local_securefiles: File not readable or is a directory. Path: "' . $real_file_path . '"');
    print_error('filenotfound', 'local_securefiles');
}

// --- Serve the File ---

// Get the filename for the Content-Disposition header.
$filename = basename($real_file_path);

// Determine the file extension.
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));

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
        $mimetype = 'application/javascript';
        break; // Official & most robust for JS
    case 'json':
        $mimetype = 'application/json';
        break;
    case 'xml':
        $mimetype = 'application/xml';
        break; // text/xml is also common, but application/xml is often preferred

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
        if ($isScormPath) {
            error_log("SecureFiles SCORM Trace: MIME determination entering DEFAULT case for Path='{$relative_file_path}', Extension='{$extension}', RealPath='{$real_file_path}'");
        }
        // If extension is not in our comprehensive list, try mime_content_type() as a fallback.
        if (function_exists('mime_content_type')) {
            $mimetypeattempt = mime_content_type($real_file_path);
            if ($isScormPath) {
                error_log("SecureFiles SCORM Trace: mime_content_type() for '{$real_file_path}' returned '{$mimetypeattempt}'");
            }
            // Only use mime_content_type's result if it's valid AND not generic octet-stream, and not empty
            if ($mimetypeattempt !== false && $mimetypeattempt !== 'application/octet-stream' && !empty($mimetypeattempt)) {
                $mimetype = $mimetypeattempt;
            }
        }
        // If still no reliable mimetype (i.e., $mimetype is still null or became empty after trying mime_content_type), fallback.
        if (empty($mimetype)) {
            $mimetype = 'application/octet-stream';
            if ($isScormPath) {
                error_log("SecureFiles SCORM Trace: MIME type for Path='{$relative_file_path}' ultimately falling back to application/octet-stream.");
            }
        }
        break;
}

// Log the final determined MIME type if it's a SCORM path, for debugging.
if ($isScormPath) {
    error_log("SecureFiles SCORM Trace: Final MIME type for Path='{$relative_file_path}', Extension='{$extension}' is '{$mimetype}'");
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
$disposition = 'inline'; // Default to inline for web/SCORM assets

// Force download for types that are typically not displayed inline or for safety.
$attachment_extensions = ['zip', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
if ($mimetype === 'application/octet-stream' || in_array($extension, $attachment_extensions)) {
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"');

// Security headers
header('X-Content-Type-Options: nosniff'); // Crucial: Prevents browser from ignoring Content-Type
header('Cache-Control: private, must-revalidate'); // Good for dynamic content access
header('Pragma: public'); // HTTP 1.0 compatibility for Cache-Control.

// Output the file contents.
if (!readfile($real_file_path)) {
    error_log('Moodle local_securefiles: readfile() failed for path: "' . $real_file_path . '"');
}

exit;
