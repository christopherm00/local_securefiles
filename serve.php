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
// UNCONDITIONAL initial log message to server logs - vital for basic execution check.
error_log("SERVE.PHP (CACHE-ADJUST DEBUG) EXECUTION ATTEMPTED - TIMESTAMP: " . time() . " - REQUEST_URI: " . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));

// --- DEBUG FLAG & HEADER COLLECTION ---
$debugSecureFiles = true; // Set to true to enable verbose logging and custom debug headers.
$debugHeaderMessages = []; // Array to collect messages for HTTP headers.

// Function to add a message to both server logs and the header collection.
if (!function_exists('add_debug_message')) {
    function add_debug_message($message, $isCritical = false) {
        global $debugSecureFiles, $debugHeaderMessages;
        $prefix = "SecureFiles Debug: ";
        if ($isCritical) {
            $prefix = "SecureFiles CRITICAL: ";
        }
        error_log($prefix . $message);
        if ($debugSecureFiles && isset($debugHeaderMessages) && is_array($debugHeaderMessages)) {
            $header_message = preg_replace('/\s+/', ' ', trim($message));
            $header_message = substr($header_message, 0, 250);
            $debugHeaderMessages[] = $header_message;
        }
    }
}

if ($debugSecureFiles) {
    add_debug_message("Script execution formally starting (debug flag is true).");
}

// Bootstrap Moodle.
require(__DIR__ . '/../../config.php');
add_debug_message("Moodle config.php loaded. URI: " . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));

// Get base path
$base_media_path_config = get_config('local_securefiles', 'base_path');
if (empty($base_media_path_config)) {
    add_debug_message("base_path setting is not configured.", true);
    print_error('config_error_basepath', 'local_securefiles');
}
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// --- MODIFICATION FOR INTERNAL ACCESS ---
$allow_internal_access = false;
$requesting_ip = getremoteaddr();
$localhost_ips = ['127.0.0.1', '::1'];
if (in_array($requesting_ip, $localhost_ips) || PHP_SAPI === 'cli') {
    $allow_internal_access = true;
    add_debug_message("Internal Moodle access condition met. IP: {$requesting_ip}, SAPI: " . PHP_SAPI . ". Bypassing require_login().");
    if (isset($USER)) {
        add_debug_message("Bypassing require_login. Current \$USER->id: " . (isset($USER->id) ? $USER->id : 'Not set/Guest'));
    } else {
        add_debug_message("Bypassing require_login. \$USER object is not set at this point.");
    }
} else {
    add_debug_message("External access attempt from IP: {$requesting_ip}. Enforcing require_login().");
    require_login();
    add_debug_message("User login confirmed (external access). \$USER->id: " . (isset($USER->id) ? $USER->id : 'N/A'));
}
// --- END OF MODIFICATION FOR INTERNAL ACCESS ---

$relative_file_path = required_param('file', PARAM_PATH);
add_debug_message("Requested relative_file_path: '{$relative_file_path}'");

$isScormPath = (stripos($relative_file_path, 'SCORM') !== false);
if ($isScormPath) {
    add_debug_message("Path identified as SCORM-related: '{$relative_file_path}'");
}

// Security checks...
if (strpos($relative_file_path, '..') !== false) {
    add_debug_message("Directory traversal attempt blocked: '{$relative_file_path}'", true);
    print_error('invalidpath', 'local_securefiles');
}
$full_file_path = $base_media_path . $relative_file_path;
add_debug_message("Constructed full_file_path: '{$full_file_path}'");
$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);
add_debug_message("real_base_path: '" . ($real_base_path ?: 'false') . "', real_file_path: '" . ($real_file_path ?: 'false') . "'");
if ($real_base_path === false) { /* ... error handling ... */
    add_debug_message("Configured base_path '{$base_media_path}' (realpath failed).", true); print_error('config_error_basepath', 'local_securefiles');}
if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) { /* ... error handling ... */
    add_debug_message("File access denied/not found or outside base. RealPath: " . ($real_file_path ?: 'false') . " RelPath: " . $relative_file_path, true); print_error('filenotfound', 'local_securefiles');}
if (!is_file($real_file_path) || !is_readable($real_file_path)) { /* ... error handling ... */
    add_debug_message("File not file or not readable: '{$real_file_path}'", true); print_error('filenotfound', 'local_securefiles');}
add_debug_message("All security checks passed for: '{$real_file_path}'");

// --- Serve the File ---
$filename = basename($real_file_path);
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
add_debug_message("Determined extension: '{$extension}' for file: '{$filename}'");

$mimetype = null;
// Switch statement for MIME types (from previous version, ensure it's complete)
switch ($extension) {
    case 'html': case 'htm': $mimetype = 'text/html'; break;
    case 'css': $mimetype = 'text/css'; break;
    case 'js':
        $mimetype = 'application/javascript';
        add_debug_message("Matched 'js', MIME: 'application/javascript'");
        break;
    case 'json': $mimetype = 'application/json'; break;
    case 'xml': $mimetype = 'application/xml'; break;
    case 'jpg': case 'jpeg': $mimetype = 'image/jpeg'; break;
    case 'png': $mimetype = 'image/png'; break;
    case 'gif': $mimetype = 'image/gif'; break;
    case 'svg': $mimetype = 'image/svg+xml'; break;
    case 'ico': $mimetype = 'image/vnd.microsoft.icon'; break;
    case 'mp3': $mimetype = 'audio/mpeg'; break;
    case 'mp4': $mimetype = 'video/mp4'; break;
    case 'webm': $mimetype = 'video/webm'; break;
    case 'ogg': $mimetype = 'application/ogg'; break;
    case 'ogv': $mimetype = 'video/ogg'; break;
    case 'oga': $mimetype = 'audio/ogg'; break;
    case 'wav': $mimetype = 'audio/wav'; break;
    case 'flv': $mimetype = 'video/x-flv'; break;
    case 'swf': $mimetype = 'application/x-shockwave-flash'; break;
    case 'woff': $mimetype = 'font/woff'; break;
    case 'woff2': $mimetype = 'font/woff2'; break;
    case 'ttf': $mimetype = 'font/ttf'; break;
    case 'otf': $mimetype = 'font/otf'; break;
    case 'eot': $mimetype = 'application/vnd.ms-fontobject'; break;
    case 'pdf': $mimetype = 'application/pdf'; break;
    case 'txt': $mimetype = 'text/plain'; break;
    case 'doc': $mimetype = 'application/msword'; break;
    case 'docx': $mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'; break;
    case 'xls': $mimetype = 'application/vnd.ms-excel'; break;
    case 'xlsx': $mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'; break;
    case 'ppt': $mimetype = 'application/vnd.ms-powerpoint'; break;
    case 'pptx': $mimetype = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'; break;
    case 'zip': $mimetype = 'application/zip'; break;
    default:
        add_debug_message("MIME DEFAULT case. Ext: '{$extension}'");
        if (function_exists('mime_content_type')) {
            $mimetypeattempt = mime_content_type($real_file_path);
            add_debug_message("mime_content_type() returned '{$mimetypeattempt}'");
            if ($mimetypeattempt !== false && $mimetypeattempt !== 'application/octet-stream' && !empty($mimetypeattempt)) {
                $mimetype = $mimetypeattempt;
            }
        }
        if (empty($mimetype)) {
            $mimetype = 'application/octet-stream';
            add_debug_message("MIME fallback to application/octet-stream.");
        }
        break;
}
add_debug_message("Final determined MIME type: '{$mimetype}'");

if (headers_sent($hs_file, $hs_line)) {
    add_debug_message("Headers already sent from {$hs_file}:{$hs_line} before main headers.", true);
    exit;
}
while (ob_get_level() > 0) { ob_end_clean(); }

if ($debugSecureFiles && !empty($debugHeaderMessages)) {
    $header_limit = 20; $count = 0;
    foreach ($debugHeaderMessages as $index => $msg) {
        if ($count >= $header_limit) { if (!headers_sent()) { header("X-ServePHP-Debug-Overflow: Too many messages."); } error_log("SecureFiles Debug: Too many debug messages for headers."); break; }
        if (!headers_sent()) { header("X-ServePHP-Debug-{$index}: " . $msg); }
        else { error_log("SecureFiles Debug: Could not send X-ServePHP-Debug-{$index} ('{$msg}') - headers sent.");}
        $count++;
    }
}

$contentTypeHeader = 'Content-Type: ' . $mimetype;
header($contentTypeHeader);
error_log("SecureFiles Final: Sending header: '{$contentTypeHeader}' for '{$filename}'");

header('Content-Length: ' . filesize($real_file_path));
$disposition = 'inline';
$attachment_extensions = ['zip', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
// Common static web asset types that should be cacheable by proxies and browsers
$static_asset_extensions = ['js', 'css', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp3', 'mp4', 'webm', 'ogg', 'ogv', 'oga', 'wav'];

if ($mimetype === 'application/octet-stream' || in_array($extension, $attachment_extensions)) {
    $disposition = 'attachment';
}
header('Content-Disposition: ' . $disposition . '; filename="' . rawurlencode($filename) . '"');

// --- Cache-Control Adjustment ---
if (in_array($extension, $static_asset_extensions) && $disposition === 'inline') {
    add_debug_message("Applying public cache for static asset: {$filename}");
    header('Cache-Control: public, max-age=604800, immutable'); // Cache for 1 week, immutable
    header_remove('Pragma'); // Pragma: public is for HTTP/1.0, less relevant with Cache-Control
    header_remove('Expires'); // Expires is for HTTP/1.0
} else {
    add_debug_message("Applying private cache for: {$filename}");
    header('Cache-Control: private, must-revalidate');
    header('Pragma: public'); // Retain for non-publicly cached items if needed
}
// --- End Cache-Control Adjustment ---

header('X-Content-Type-Options: nosniff');

add_debug_message("All headers sent. Attempting to readfile: '{$real_file_path}'");

if (!readfile($real_file_path)) {
    add_debug_message("readfile() FAILED for '{$real_file_path}'", true);
} else {
    add_debug_message("readfile() SUCCEEDED for '{$real_file_path}'");
}

add_debug_message("Script execution finished.");
exit;