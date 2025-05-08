<?php
/**
 * Capabilities definition for the local_securefiles plugin.
 *
 * @package   local_securefiles
 * @copyright 2025 Christopher Murad - Moodle Contractor
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$capabilities = array(
    // For now, we are primarily using require_login() in serve.php, which checks
    // if the user is a logged-in Moodle user.

    // If you wanted more granular control, for example, to allow only users with a
    // specific role to access files through this plugin, you could define a capability:
    /*
    'local/securefiles:viewfiles' => array(
        'captype' => 'read', // 'read' or 'write'
        'contextlevel' => CONTEXT_SYSTEM, // Or CONTEXT_COURSE, CONTEXT_USER etc.
        'archetypes' => array( // Default permissions for standard roles
            'student' => CAP_ALLOW,
            'teacher' => CAP_ALLOW,
            'editingteacher' => CAP_ALLOW,
            'manager' => CAP_ALLOW,
            'user' => CAP_ALLOW, // Authenticated user
        ),
        // 'clonepermissionsfrom' => 'moodle/site:viewparticipants', // Optionally clone from another capability
    ),
    */
    // If you define a capability like above, you would then check it in serve.php using:
    // require_capability('local/securefiles:viewfiles', context_system::instance());
);

