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
error_log("SERVE.PHP (HTTP HEADER DEBUG) EXECUTION ATTEMPTED - TIMESTAMP: " . time() . " - REQUEST_URI: " . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));

// --- DEBUG FLAG & HEADER COLLECTION ---
$debugSecureFiles = true; // Set to true to enable verbose logging and custom debug headers.
$debugHeaderMessages = []; // Array to collect messages for HTTP headers.

if ($debugSecureFiles) {
    $debugHeaderMessages[] = "Script execution formally starting.";
    error_log("SecureFiles Debug (Headers): Script execution formally starting.");
}

// Function to add a message to both server logs and the header collection.
function add_debug_message($message, $isCritical = false) {
    global $debugSecureFiles, $debugHeaderMessages;
    $prefix = "SecureFiles Debug (Headers): ";
    if ($isCritical) {
        $prefix = "SecureFiles CRITICAL (Headers): ";
    }
    error_log($prefix . $message); // Always log to server error log.
    if ($debugSecureFiles) {
        // Sanitize message for header: remove newlines, limit length if necessary.
        $header_message = preg_replace('/\s+/', ' ', trim($message)); // Replace newlines/multiple spaces with a single space
        $header_message = substr($header_message, 0, 250); // Basic length limit for header value
        $debugHeaderMessages[] = $header_message;
    }
}

// Bootstrap Moodle.
require(__DIR__ . '/../../config.php'); // This needs to succeed.
add_debug_message("Moodle config.php loaded. URI: " . (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A'));


// Get the configured base path for media files from plugin settings.
$base_media_path_config = get_config('local_securefiles', 'base_path');
if (empty($base_media_path_config)) {
    add_debug_message("base_path setting is not configured.", true);
    print_error('config_error_basepath', 'local_securefiles'); // Moodle function, will halt.
}
$base_media_path = rtrim($base_media_path_config, '/\\') . DIRECTORY_SEPARATOR;

// Require the user to be logged in.
require_login(); // Moodle function, will halt if not logged in.
add_debug_message("User login confirmed.");

// Get the requested relative file path from the 'file' GET parameter.
$relative_file_path = required_param('file', PARAM_PATH); // Moodle function
add_debug_message("Requested relative_file_path: '{$relative_file_path}'");

// --- SCORM Path Detection ---
$isScormPath = (stripos($relative_file_path, 'SCORM') !== false);
if ($isScormPath) {
    add_debug_message("Path identified as SCORM-related based on 'SCORM' string in path: '{$relative_file_path}'");
}

// --- Security Checks ---
if (strpos($relative_file_path, '..') !== false) {
    add_debug_message("Directory traversal attempt blocked for path: '{$relative_file_path}'", true);
    print_error('invalidpath', 'local_securefiles');
}

$full_file_path = $base_media_path . $relative_file_path;
add_debug_message("Constructed full_file_path: '{$full_file_path}'");

$real_base_path = realpath($base_media_path);
$real_file_path = realpath($full_file_path);
add_debug_message("real_base_path: '" . ($real_base_path ? $real_base_path : 'false (realpath failed)') . "', real_file_path: '" . ($real_file_path ? $real_file_path : 'false (realpath failed)') . "'");

if ($real_base_path === false) {
    add_debug_message("Configured base_path '{$base_media_path}' (realpath failed) is invalid or not accessible.", true);
    print_error('config_error_basepath', 'local_securefiles');
}

if ($real_file_path === false || strpos($real_file_path, $real_base_path) !== 0) {
    add_debug_message("File access denied/not found or outside base. RealPath: " . ($real_file_path ?: 'false') . " RelPath: " . $relative_file_path, true);
    print_error('filenotfound', 'local_securefiles');
}

if (!is_file($real_file_path) || !is_readable($real_file_path)) {
    add_debug_message("File not a file or not readable: '{$real_file_path}'. is_file: " . (is_file($real_file_path) ? 'true' : 'false') . ", is_readable: " . (is_readable($real_file_path) ? 'true' : 'false'), true);
    print_error('filenotfound', 'local_securefiles');
}
add_debug_message("All security checks passed for: '{$real_file_path}'");

// --- Serve the File ---
$filename = basename($real_file_path);
$extension = strtolower(pathinfo($real_file_path, PATHINFO_EXTENSION));
add_debug_message("Determined extension: '{$extension}' for file: '{$filename}'");

$mimetype = null;
switch ($extension) {
    case 'html': case 'htm': $mimetype = 'text/html'; break;
    case 'css': $mimetype = 'text/css'; break;
    case 'js':
        $mimetype = 'application/javascript';
        add_debug_message("Matched extension 'js', explicitly setting MIME to 'application/javascript'");
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
        add_debug_message("MIME determination entering DEFAULT case. Ext: '{$extension}'");
        if (function_exists('mime_content_type')) {
            $mimetypeattempt = mime_content_type($real_file_path);
            add_debug_message("mime_content_type() for '{$real_file_path}' returned '{$mimetypeattempt}'");
            if ($mimetypeattempt !== false && $mimetypeattempt !== 'application/octet-stream' && !empty($mimetypeattempt)) {
                $mimetype = $mimetypeattempt;
            }
        }
        if (empty($mimetype)) {
            $mimetype = 'application/octet-stream';
            add_debug_message("MIME type ultimately falling back to application/octet-stream.");
        }
        break;
}
add_debug_message("Final determined MIME type: '{$mimetype}'");

// Ensure no output has been sent yet before sending headers.
if (headers_sent($hs_file, $hs_line)) {
    add_debug_message("Headers already sent from {$hs_file}:{$hs_line} before main file headers could be set.", true);
    // Cannot proceed to send file if headers are already sent by an error/Moodle output.
    // The script might have already been terminated by print_error or similar.
    // If not, this is a critical state.
    exit;
}

// Clear any stray output buffers.
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Send collected debug messages as custom headers if debug mode is on.
if ($debugSecureFiles && !empty($debugHeaderMessages)) {
    $header_limit = 20; // Limit number of debug headers to prevent excessively large header blocks
    $count = 0;
    foreach ($debugHeaderMessages as $index => $msg) {
        if ($count >= $header_limit) {
            header("X-ServePHP-Debug-Overflow: Too many debug messages, rest in server log.");
            error_log("SecureFiles Debug (Headers): Too many debug messages for headers. Remainder in server log only.");
            break;
        }
        // Header names should not contain spaces and be somewhat unique.
        // Using X-ServePHP-Debug-0, X-ServePHP-Debug-1 etc.
        header("X-ServePHP-Debug-{$index}: " . $msg);
        $count++;
    }
}

// Set main file headers.
$contentTypeHeader = 'Content-Type: ' . $mimetype;
header($contentTypeHeader);
error_log("SecureFiles Final: Sending header: '{$contentTypeHeader}' for file '{$filename}'"); // Server log

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

add_debug_message("All headers sent. Attempting to readfile: '{$real_file_path}'");

if (!readfile($real_file_path)) {
    add_debug_message("readfile() FAILED for path: '{$real_file_path}'", true);
} else {
    add_debug_message("readfile() SUCCEEDED for path: '{$real_file_path}'");
}

add_debug_message("Script execution finished.");
exit;