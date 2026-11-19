<?php
// Built by Abdur Rahman
declare(strict_types=1);

// Load centralized local/live configuration (never tracked in source control)
$localConfigFile = __DIR__ . '/config.local.php';
if (is_file($localConfigFile)) {
    require_once $localConfigFile;
}

if (!defined('PORTAL_ENV')) {
    $envMode = strtolower(trim((string)(getenv('PORTAL_ENV') ?: 'xampp')));
    define('PORTAL_ENV', in_array($envMode, ['live', 'production', 'prod'], true) ? 'live' : 'xampp');
}
define('IS_LIVE_ENV', in_array(strtolower((string)PORTAL_ENV), ['live', 'production', 'prod'], true));

// Resolve selected profile from $PORTAL_ENVIRONMENTS if provided in config.local.php
$activeProfile = [];
if (isset($PORTAL_ENVIRONMENTS) && is_array($PORTAL_ENVIRONMENTS)) {
    $envKey = IS_LIVE_ENV ? 'live' : 'xampp';
    if (isset($PORTAL_ENVIRONMENTS[$envKey]) && is_array($PORTAL_ENVIRONMENTS[$envKey])) {
        $activeProfile = $PORTAL_ENVIRONMENTS[$envKey];
    }
}

$cfg = static function (string $key, mixed $fallback = '') use ($activeProfile): mixed {
    if (defined($key)) {
        return constant($key);
    }
    if (array_key_exists($key, $activeProfile)) {
        return $activeProfile[$key];
    }
    $envVal = getenv($key);
    return $envVal !== false ? $envVal : $fallback;
};

// Auto-detect current server base URL when APP_URL is not explicitly configured
function detectPortalBaseUrl(): string {
    $host = trim((string)($_SERVER['HTTP_HOST'] ?? ''));
    if ($host === '') {
        return 'http://localhost/assetcare';
    }
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    $scheme = $isHttps ? 'https' : 'http';
    $baseDir = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? ''))), '/');
    return $scheme . '://' . $host . ($baseDir === '/' ? '' : $baseDir);
}

// MySQL / phpMyAdmin Configuration
if (!defined('DB_HOST')) define('DB_HOST', (string)$cfg('DB_HOST', '127.0.0.1'));
if (!defined('DB_PORT')) define('DB_PORT', (int)$cfg('DB_PORT', 3306));
if (!defined('DB_NAME')) define('DB_NAME', (string)$cfg('DB_NAME', 'assetcare_db'));
if (!defined('DB_USER')) define('DB_USER', (string)$cfg('DB_USER', 'root'));
if (!defined('DB_PASS')) define('DB_PASS', (string)$cfg('DB_PASS', ''));
if (!defined('DB_CHARSET')) define('DB_CHARSET', 'utf8mb4');

// SMTP Mail Configuration
if (!defined('SMTP_HOST')) define('SMTP_HOST', (string)$cfg('SMTP_HOST', 'smtp.gmail.com'));
if (!defined('SMTP_PORT')) define('SMTP_PORT', (int)$cfg('SMTP_PORT', 587));
if (!defined('SMTP_USER')) define('SMTP_USER', (string)$cfg('SMTP_USER', ''));
if (!defined('SMTP_PASS')) define('SMTP_PASS', (string)$cfg('SMTP_PASS', ''));
if (!defined('SMTP_FROM_NAME')) define('SMTP_FROM_NAME', (string)$cfg('SMTP_FROM_NAME', 'AssetCare'));

// Portal URL and comma-separated trusted CORS origins
$resolvedAppUrl = rtrim((string)$cfg('APP_URL', ''), '/');
if (!defined('APP_URL')) {
    define('APP_URL', $resolvedAppUrl !== '' ? $resolvedAppUrl : detectPortalBaseUrl());
}
if (!defined('ALLOWED_ORIGINS')) {
    define('ALLOWED_ORIGINS', (string)$cfg('ALLOWED_ORIGINS', ''));
}
