<?php
// Built by Abdur Rahman
declare(strict_types=1);

@ini_set('display_errors', '0');
@ini_set('html_errors', '0');
@error_reporting(E_ALL);
if (ob_get_level() === 0) {
    ob_start();
}

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/mail.php';

@header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

function isAllowedCorsOriginPhp(string $originHeader): bool {
    if ($originHeader === '') return false;
    $parts = @parse_url($originHeader);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) return false;
    $scheme = strtolower((string)$parts['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) return false;

    $originHost = strtolower((string)$parts['host']) . (isset($parts['port']) ? ':' . (int)$parts['port'] : '');
    $originHostname = strtolower((string)$parts['host']);

    if (!IS_LIVE_ENV && in_array($originHostname, ['localhost', '127.0.0.1'], true)) {
        return true;
    }

    $reqHost = strtolower(trim((string)($_SERVER['HTTP_HOST'] ?? '')));
    if ($reqHost !== '' && $originHost === $reqHost) {
        return true;
    }

    $extraRaw = (defined('APP_URL') ? APP_URL : '') . ',' . (defined('ALLOWED_ORIGINS') ? ALLOWED_ORIGINS : '');
    foreach (explode(',', $extraRaw) as $candidate) {
        $candidate = trim($candidate);
        if ($candidate === '') continue;
        $cParts = @parse_url($candidate);
        if (is_array($cParts) && !empty($cParts['host'])) {
            $cHost = strtolower((string)$cParts['host']) . (isset($cParts['port']) ? ':' . (int)$cParts['port'] : '');
            if ($originHost === $cHost) return true;
        } elseif ($originHost === strtolower($candidate)) {
            return true;
        }
    }
    return false;
}

$incomingOrigin = trim((string)($_SERVER['HTTP_ORIGIN'] ?? ''));
$corsAllowed = $incomingOrigin !== '' && isAllowedCorsOriginPhp($incomingOrigin);
if ($corsAllowed) {
    header('Access-Control-Allow-Origin: ' . $incomingOrigin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Auth-Token');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(($incomingOrigin === '' || $corsAllowed) ? 200 : 403);
    exit;
}

function jsonResponse(array $payload, int $status = 200): void {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    }
    $encoded = json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
    );
    if ($encoded === false) {
        echo '{"success":false,"message":"Failed to encode server response."}';
    } else {
        echo $encoded;
    }
    exit;
}

function getClientIp(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
}

function getRequestJson(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return $_POST;
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : $_POST;
}

function getAuthTokenFromRequest(): string {
    $candidates = [];
    if (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) {
        $candidates[] = (string)$_SERVER['HTTP_X_AUTH_TOKEN'];
    }
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $candidates[] = (string)$_SERVER['HTTP_AUTHORIZATION'];
    }
    if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        $candidates[] = (string)$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            foreach ($headers as $k => $v) {
                $lk = strtolower((string)$k);
                if ($lk === 'x-auth-token') {
                    return trim((string)$v);
                }
                if ($lk === 'authorization') {
                    $candidates[] = (string)$v;
                }
            }
        }
    }

    foreach ($candidates as $val) {
        $val = trim($val);
        if ($val === '') continue;
        if (stripos($val, 'Bearer ') === 0) {
            return trim(substr($val, 7));
        }
        return $val;
    }
    return '';
}

define('SESSION_TTL_MS', 12 * 60 * 60 * 1000);

function authenticateRequest(PDO $pdo): ?array {
    $token = getAuthTokenFromRequest();
    if ($token === '') {
        return null;
    }
    $user = findUserByToken($pdo, $token);
    if (!$user) {
        return null;
    }
    if ($user['status'] === 'blocked' || $user['status'] === 'pending') {
        return null;
    }
    $expiresAt = (int)($user['token_expires_at'] ?? 0);
    if ($expiresAt > 0 && nowMs() > $expiresAt) {
        $clr = $pdo->prepare("UPDATE users SET api_token = NULL, token_expires_at = NULL, lastSeen = 0 WHERE username = ?");
        $clr->execute([$user['username']]);
        return null;
    }
    return $user;
}

function sanitizePortalRedirectUrlPhp(?string $candidate, string $fallback): string {
    $cand = trim((string)($candidate ?? ''));
    if ($cand === '') return $fallback;
    $p = @parse_url($cand);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) return $fallback;
    $scheme = strtolower((string)$p['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) return $fallback;
    $candHost = strtolower((string)$p['host']) . (isset($p['port']) ? ':' . (int)$p['port'] : '');

    $allowedHosts = [];
    $fParts = @parse_url($fallback);
    if (is_array($fParts) && !empty($fParts['host'])) {
        $allowedHosts[] = strtolower((string)$fParts['host']) . (isset($fParts['port']) ? ':' . (int)$fParts['port'] : '');
    }
    $appParts = @parse_url(APP_URL);
    if (is_array($appParts) && !empty($appParts['host'])) {
        $allowedHosts[] = strtolower((string)$appParts['host']) . (isset($appParts['port']) ? ':' . (int)$appParts['port'] : '');
    }
    if (in_array($candHost, $allowedHosts, true)) {
        return rtrim($cand, '/');
    }
    return $fallback;
}

function checkRateLimit(PDO $pdo, string $key, int $maxAttempts = 5, int $windowMs = 60000, int $blockDurationMs = 300000): array {
    $now = nowMs();
    $stmt = $pdo->prepare("SELECT * FROM auth_rate_limits WHERE rate_key = ? LIMIT 1");
    $stmt->execute([$key]);
    $record = $stmt->fetch();

    if ($record && $record['blocked_until'] !== null && (int)$record['blocked_until'] > $now) {
        $waitSeconds = (int)ceil(((int)$record['blocked_until'] - $now) / 1000);
        return ['allowed' => false, 'waitSeconds' => $waitSeconds];
    }

    if (!$record || ($now - (int)$record['last_attempt']) > $windowMs) {
        $up = $pdo->prepare("INSERT INTO auth_rate_limits (rate_key, attempts, last_attempt, blocked_until) VALUES (?, 1, ?, NULL) ON DUPLICATE KEY UPDATE attempts = 1, last_attempt = VALUES(last_attempt), blocked_until = NULL");
        $up->execute([$key, $now]);
        return ['allowed' => true];
    }

    $attempts = (int)$record['attempts'] + 1;
    $blockedUntil = null;
    if ($attempts > $maxAttempts) {
        $blockedUntil = $now + $blockDurationMs;
        $up = $pdo->prepare("UPDATE auth_rate_limits SET attempts = ?, last_attempt = ?, blocked_until = ? WHERE rate_key = ?");
        $up->execute([$attempts, $now, $blockedUntil, $key]);
        $waitSeconds = (int)ceil($blockDurationMs / 1000);
        return ['allowed' => false, 'waitSeconds' => $waitSeconds];
    }

    $up = $pdo->prepare("UPDATE auth_rate_limits SET attempts = ?, last_attempt = ? WHERE rate_key = ?");
    $up->execute([$attempts, $now, $key]);
    return ['allowed' => true];
}

function resetRateLimit(PDO $pdo, string $key): void {
    $stmt = $pdo->prepare("DELETE FROM auth_rate_limits WHERE rate_key = ?");
    $stmt->execute([$key]);
}

function isQuantaniteEmail(string $email): bool {
    return (bool)preg_match('/^[^\s@]+@quantanite\.com$/i', trim($email));
}

function verifyPortalPassword(string $plain, string $hash): bool {
    if ($plain === '' || $hash === '') {
        return false;
    }
    return password_verify($plain, $hash);
}

function aggregateSlotAccessoriesPhp(array $slotAssets, array $existingAccessories): array {
    $existingMap = [];
    foreach ($existingAccessories as $acc) {
        if (!is_array($acc)) continue;
        $key = strtolower(trim((string)($acc['product'] ?? '')));
        if ($key !== '') {
            $existingMap[$key] = $acc;
        }
    }

    $aggregated = [];
    foreach ($slotAssets as $entry) {
        $recs = is_array($entry['recommendations'] ?? null) ? $entry['recommendations'] : [];
        foreach ($recs as $rec) {
            $cleaned = trim((string)$rec);
            if ($cleaned === '') continue;
            $key = strtolower($cleaned);
            if (isset($aggregated[$key])) {
                $aggregated[$key]['qty'] += 1;
            } else {
                $existing = $existingMap[$key] ?? null;
                $aggregated[$key] = [
                    'product' => ($existing && !empty($existing['product'])) ? (string)$existing['product'] : $cleaned,
                    'brand' => ($existing && isset($existing['brand'])) ? (string)$existing['brand'] : '',
                    'model' => ($existing && isset($existing['model'])) ? (string)$existing['model'] : '',
                    'qty' => 1,
                    'remarks' => ($existing && isset($existing['remarks'])) ? (string)$existing['remarks'] : ''
                ];
            }
        }
    }

    return array_values($aggregated);
}

function sqlEscape(string $value): string {
    return str_replace(
        ["\\", "\0", "\n", "\r", "'", "\x1a"],
        ["\\\\", "\\0", "\\n", "\\r", "\\'", "\\Z"],
        $value
    );
}

try {
    $pdo = getDbConnection();
    $data = getRequestJson();
    $action = trim((string)($_GET['action'] ?? ($data['action'] ?? '')));
    if ($action === '' && !empty($_SERVER['PATH_INFO'])) {
        $action = trim((string)$_SERVER['PATH_INFO'], '/');
    }

    $clientIp = getClientIp();

    // 0. PUBLIC HEALTH DIAGNOSTIC (sensitive DB/table metadata restricted to authenticated admins)
    if ($action === 'health') {
        $authUser = authenticateRequest($pdo);
        if ($authUser && $authUser['role'] === 'admin') {
            $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
            jsonResponse([
                'success' => true,
                'status' => 'ok',
                'database' => DB_NAME,
                'dataVersion' => getDataVersion($pdo),
                'tables' => is_array($tables) ? $tables : [],
                'serverTime' => nowMs()
            ]);
        }
        jsonResponse([
            'success' => true,
            'status' => 'ok',
            'serverTime' => nowMs()
        ]);
    }

    // 1. LOGIN
    if ($action === 'login') {
        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');

        if ($username === '' || $password === '') {
            jsonResponse(['success' => false, 'message' => 'Please enter both username and password.'], 400);
        }

        $user = findUser($pdo, $username);
        if ($user && $user['status'] === 'blocked') {
            jsonResponse([
                'success' => false,
                'code' => 'ACCOUNT_BLOCKED',
                'message' => 'This Account Has Been Blocked by The Admin'
            ], 200);
        }

        $rateCheck = checkRateLimit($pdo, "login:$clientIp:" . strtolower($username), 5, 60000, 120000);
        if (!$rateCheck['allowed']) {
            $wait = (int)$rateCheck['waitSeconds'];
            jsonResponse([
                'success' => false,
                'code' => 'ACCOUNT_LOCKED',
                'waitSeconds' => $wait,
                'message' => "Account temporarily locked due to too many failed attempts. Please try again in {$wait}s."
            ], 429);
        }

        if (!$user) {
            jsonResponse(['success' => false, 'message' => 'Invalid Username or Password.'], 401);
        }

        if ($user['status'] === 'pending') {
            jsonResponse(['success' => false, 'message' => 'Your account is pending approval.'], 403);
        }

        $isValid = verifyPortalPassword($password, (string)$user['passwordHash']);

        if (!$isValid) {
            jsonResponse(['success' => false, 'message' => 'Invalid Username or Password.'], 401);
        }

        resetRateLimit($pdo, "login:$clientIp:" . strtolower($username));

        $token = bin2hex(random_bytes(32));
        $now = nowMs();
        $tokenExpiresAt = $now + SESSION_TTL_MS;
        $upd = $pdo->prepare("UPDATE users SET api_token = ?, token_expires_at = ?, lastSeen = ? WHERE username = ?");
        $upd->execute([$token, $tokenExpiresAt, $now, $user['username']]);

        $safeUser = [
            'username' => (string)$user['username'],
            'email' => (string)$user['email'],
            'role' => (string)$user['role'],
            'status' => (string)$user['status'],
            'mustResetPassword' => (int)$user['mustResetPassword'],
            'api_token' => $token
        ];

        jsonResponse(['success' => true, 'user' => $safeUser]);
    }

    // 2. REQUEST OTP RESET CODE
    if ($action === 'request_reset_code') {
        $username = trim((string)($data['username'] ?? ''));
        $email = strtolower(trim((string)($data['email'] ?? '')));

        if ($username === '' || $email === '') {
            jsonResponse(['success' => false, 'message' => 'Username and email are required.'], 400);
        }

        if (!isQuantaniteEmail($email)) {
            jsonResponse([
                'success' => false,
                'message' => 'Invalid email domain! Only registered @quantanite.com email addresses are allowed.'
            ], 400);
        }

        $rateCheck = checkRateLimit($pdo, "otp:$clientIp:" . strtolower($username), 3, 60000, 180000);
        if (!$rateCheck['allowed']) {
            $wait = (int)$rateCheck['waitSeconds'];
            jsonResponse([
                'success' => false,
                'message' => "Too many requests. Please wait {$wait}s before requesting a new code."
            ], 429);
        }

        $user = findUser($pdo, $username);
        if (!$user || strtolower(trim((string)$user['email'])) !== $email) {
            jsonResponse([
                'success' => false,
                'message' => 'Unregistered username or @quantanite.com email address. Please enter your registered account details.'
            ], 400);
        }

        if ($user['status'] === 'blocked') {
            jsonResponse([
                'success' => false,
                'code' => 'ACCOUNT_BLOCKED',
                'message' => 'This Account Has Been Blocked by The Admin'
            ], 200);
        }

        if ($user['status'] !== 'active') {
            jsonResponse(['success' => false, 'message' => 'Your account is not active for password recovery.'], 403);
        }

        $otp = (string)random_int(100000, 999999);
        $otpHash = password_hash($otp, PASSWORD_BCRYPT);
        $expiresAt = gmdate('Y-m-d\TH:i:s.v\Z', time() + 60);

        $upd = $pdo->prepare("UPDATE users SET reset_code = ?, reset_expires = ? WHERE username = ?");
        $upd->execute([$otpHash, $expiresAt, $user['username']]);

        $sent = sendOtpEmail((string)$user['email'], (string)$user['username'], $otp);
        if (!$sent) {
            error_log("[AssetCare SMTP Warning] Failed sending OTP to {$user['email']}");
        }

        jsonResponse([
            'success' => true,
            'message' => 'A 6-digit security verification code has been sent to your registered @quantanite.com email (valid for 1 minute).'
        ]);
    }

    // 3. VERIFY RESET CODE
    if ($action === 'verify_reset_code') {
        $username = trim((string)($data['username'] ?? ''));
        $code = trim((string)($data['code'] ?? ''));

        if ($username === '' || $code === '') {
            jsonResponse(['success' => false, 'message' => 'Username and code are required.'], 400);
        }

        $otpRate = checkRateLimit($pdo, "verify_otp:$clientIp:" . strtolower($username), 5, 60000, 180000);
        if (!$otpRate['allowed']) {
            $wait = (int)$otpRate['waitSeconds'];
            jsonResponse([
                'success' => false,
                'message' => "Too many invalid verification attempts. Please wait {$wait}s."
            ], 429);
        }

        $user = findUser($pdo, $username);
        if ($user && !empty($user['reset_code']) && !empty($user['reset_expires'])) {
            $expTs = strtotime((string)$user['reset_expires']);
            if ($expTs !== false && $expTs >= time()) {
                if (verifyPortalPassword($code, (string)$user['reset_code'])) {
                    resetRateLimit($pdo, "verify_otp:$clientIp:" . strtolower($username));
                    $clrOtp = $pdo->prepare("UPDATE users SET reset_code = NULL, reset_expires = NULL WHERE username = ?");
                    $clrOtp->execute([$user['username']]);

                    $resetSessionToken = bin2hex(random_bytes(32));
                    $sessExp = nowMs() + 15 * 60 * 1000;
                    $ins = $pdo->prepare("INSERT INTO password_reset_sessions (token, username, expires_at) VALUES (?, ?, ?)");
                    $ins->execute([$resetSessionToken, $user['username'], $sessExp]);

                    jsonResponse([
                        'success' => true,
                        'resetSessionToken' => $resetSessionToken,
                        'message' => 'Code verified successfully.'
                    ]);
                }
            }
        }

        jsonResponse(['success' => false, 'message' => 'Invalid or expired security code.'], 400);
    }

    // 4. RESET PASSWORD
    if ($action === 'reset_password') {
        $username = trim((string)($data['username'] ?? ''));
        $newPass = (string)($data['newPassword'] ?? '');
        $resetSessionToken = trim((string)($data['resetSessionToken'] ?? ''));

        $currentUser = authenticateRequest($pdo);
        $isSelfForceReset = (
            $currentUser !== null &&
            strtolower((string)$currentUser['username']) === strtolower($username) &&
            (int)$currentUser['mustResetPassword'] === 1
        );

        $canonicalUsername = $currentUser ? (string)$currentUser['username'] : $username;
        $isTokenAuthorized = false;

        if ($resetSessionToken !== '') {
            $stmt = $pdo->prepare("SELECT * FROM password_reset_sessions WHERE token = ? LIMIT 1");
            $stmt->execute([$resetSessionToken]);
            $sess = $stmt->fetch();
            if ($sess && strtolower((string)$sess['username']) === strtolower($username) && (int)$sess['expires_at'] > nowMs()) {
                $isTokenAuthorized = true;
                $canonicalUsername = (string)$sess['username'];
            }
        }

        if (!$isSelfForceReset && !$isTokenAuthorized) {
            jsonResponse(['success' => false, 'message' => 'Unauthorized password reset attempt.'], 403);
        }

        $existingTargetUser = findUser($pdo, $canonicalUsername);
        if (!$existingTargetUser) {
            jsonResponse(['success' => false, 'message' => 'User not found.'], 404);
        }

        if (strlen($newPass) < 8) {
            jsonResponse(['success' => false, 'message' => 'Password must be at least 8 characters long.'], 400);
        }

        $newHash = password_hash($newPass, PASSWORD_BCRYPT);
        if ($isSelfForceReset) {
            $upd = $pdo->prepare("UPDATE users SET passwordHash = ?, mustResetPassword = 0, reset_code = NULL, reset_expires = NULL WHERE username = ?");
            $upd->execute([$newHash, $existingTargetUser['username']]);
        } else {
            $upd = $pdo->prepare("UPDATE users SET passwordHash = ?, mustResetPassword = 0, reset_code = NULL, reset_expires = NULL, api_token = NULL, token_expires_at = NULL WHERE username = ?");
            $upd->execute([$newHash, $existingTargetUser['username']]);
        }
        bumpDataVersion($pdo);

        if ($resetSessionToken !== '') {
            $del = $pdo->prepare("DELETE FROM password_reset_sessions WHERE token = ?");
            $del->execute([$resetSessionToken]);
        }

        jsonResponse(['success' => true, 'message' => 'Password has been updated successfully.']);
    }

    // AUTHENTICATION REQUIRED FOR ALL REMAINING ACTIONS
    $currentUser = authenticateRequest($pdo);
    if (!$currentUser) {
        jsonResponse([
            'success' => false,
            'message' => 'Unauthorized access. Please log in.',
            'authenticated' => false
        ], 401);
    }

    // 5. LOAD ALL DATA
    if ($action === 'load') {
        $updSeen = $pdo->prepare("UPDATE users SET lastSeen = ? WHERE username = ?");
        $updSeen->execute([nowMs(), $currentUser['username']]);

        $userRows = $pdo->query("SELECT * FROM users")->fetchAll();
        $users = array_map(
            fn($u) => formatPublicUserForViewer($u, (string)$currentUser['role'], (string)$currentUser['username']),
            $userRows
        );

        $assetRows = $pdo->query("SELECT * FROM assets")->fetchAll();
        $assets = array_map('formatAssetRow', $assetRows);

        $slotRows = $pdo->query("SELECT * FROM slots ORDER BY id DESC")->fetchAll();
        $slots = array_map('formatSlotRow', $slotRows);

        $vendorRows = $pdo->query("SELECT * FROM vendors ORDER BY companyName ASC")->fetchAll();
        $vendors = array_map('formatVendorRow', $vendorRows);

        $prodRows = $pdo->query("SELECT productName FROM assessment_products ORDER BY productName ASC")->fetchAll();
        $assessmentProducts = array_map(fn($r) => (string)$r['productName'], $prodRows);

        if (count($assessmentProducts) === 0 && count($slots) > 0) {
            $backfillNames = [];
            foreach ($slots as $sl) {
                if (is_array($sl['slotAssets'] ?? null)) {
                    foreach (extractSlotAssessmentProductNamesPhp($sl['slotAssets']) as $pName) {
                        $backfillNames[] = $pName;
                    }
                }
            }
            if (count($backfillNames) > 0) {
                $assessmentProducts = syncAssessmentProductsPhp($pdo, $backfillNames);
            }
        }

        jsonResponse([
            'success' => true,
            'users' => $users,
            'assets' => $assets,
            'slots' => $slots,
            'vendors' => $vendors,
            'assessmentProducts' => $assessmentProducts,
            'dataVersion' => getDataVersion($pdo),
            'serverTime' => nowMs()
        ]);
    }

    // 6. CHANGE PASSWORD
    if ($action === 'change_password') {
        $currentPass = (string)($data['currentPass'] ?? '');
        $newPass = (string)($data['newPass'] ?? '');

        if ($currentPass === '') {
            jsonResponse(['success' => false, 'message' => 'Please enter your current password.'], 400);
        }

        $user = findUser($pdo, (string)$currentUser['username']);
        if (!$user) {
            jsonResponse(['success' => false, 'message' => 'User not found.'], 404);
        }

        if (!verifyPortalPassword($currentPass, (string)$user['passwordHash'])) {
            jsonResponse(['success' => false, 'message' => 'Current password is incorrect.'], 400);
        }

        if (strlen($newPass) < 8) {
            jsonResponse(['success' => false, 'message' => 'New password must be at least 8 characters long.'], 400);
        }

        $newHash = password_hash($newPass, PASSWORD_BCRYPT);
        $upd = $pdo->prepare("UPDATE users SET passwordHash = ?, mustResetPassword = 0 WHERE username = ?");
        $upd->execute([$newHash, $user['username']]);
        bumpDataVersion($pdo);

        jsonResponse(['success' => true, 'message' => 'Password changed successfully.']);
    }

    // 7. PING
    if ($action === 'ping') {
        $updSeen = $pdo->prepare("UPDATE users SET lastSeen = ? WHERE username = ?");
        $updSeen->execute([nowMs(), $currentUser['username']]);

        $presence = $pdo->query("SELECT username, lastSeen FROM users")->fetchAll();
        $presenceFormatted = array_map(fn($r) => [
            'username' => (string)$r['username'],
            'lastSeen' => (int)$r['lastSeen']
        ], $presence);

        jsonResponse([
            'success' => true,
            'serverTime' => nowMs(),
            'dataVersion' => getDataVersion($pdo),
            'presence' => $presenceFormatted
        ]);
    }

    // 8. LOGOUT
    if ($action === 'logout') {
        $upd = $pdo->prepare("UPDATE users SET lastSeen = 0, api_token = NULL, token_expires_at = NULL WHERE username = ?");
        $upd->execute([$currentUser['username']]);
        jsonResponse(['success' => true]);
    }

    // 9 & 10. ADMIN USER MANAGEMENT
    if ($action === 'save_user' || $action === 'delete_user') {
        if ($currentUser['role'] !== 'admin') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Admin role required.'], 403);
        }

        if ($action === 'save_user') {
            $targetUsername = trim((string)($data['username'] ?? ''));
            if ($targetUsername === '') {
                jsonResponse(['success' => false, 'message' => 'Username is required.'], 400);
            }

            $existingUser = findUser($pdo, $targetUsername);
            $email = isset($data['email']) ? strtolower(trim((string)$data['email'])) : ($existingUser['email'] ?? '');
            $rawPassword = $data['password'] ?? '';
            $role = isset($data['role']) ? trim((string)$data['role']) : ($existingUser['role'] ?? 'Maintenance');
            $status = isset($data['status']) ? trim((string)$data['status']) : ($existingUser['status'] ?? 'active');
            $mustResetPassword = isset($data['mustResetPassword'])
                ? (int)$data['mustResetPassword']
                : ($existingUser ? (int)$existingUser['mustResetPassword'] : 1);

            if (!in_array($role, ['admin', 'Maintenance', 'IT Support', 'Management'], true)) {
                jsonResponse(['success' => false, 'message' => 'Invalid user role specified.'], 400);
            }
            if (!in_array($status, ['active', 'blocked', 'pending'], true)) {
                jsonResponse(['success' => false, 'message' => 'Invalid user status specified.'], 400);
            }
            if (isset($data['email']) && $email !== '' && !isQuantaniteEmail($email)) {
                jsonResponse(['success' => false, 'message' => 'Only valid @quantanite.com email addresses are allowed.'], 400);
            }

            if ($rawPassword !== '' && $rawPassword !== null) {
                if (!$existingUser) {
                    $chk = $pdo->prepare("SELECT username FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
                    $chk->execute([$email]);
                    if ($chk->fetch()) {
                        jsonResponse(['success' => false, 'message' => 'This email is already in use.'], 400);
                    }
                }
                if (strlen((string)$rawPassword) < 8) {
                    jsonResponse(['success' => false, 'message' => 'Password must be at least 8 characters long.'], 400);
                }
                $passwordHash = password_hash((string)$rawPassword, PASSWORD_BCRYPT);
            } else {
                if (!$existingUser) {
                    jsonResponse(['success' => false, 'message' => 'Password required for new account.'], 400);
                }
                if (isset($data['email']) && $email !== '') {
                    $chk = $pdo->prepare("SELECT username FROM users WHERE LOWER(username) <> LOWER(?) AND LOWER(email) = LOWER(?) LIMIT 1");
                    $chk->execute([$existingUser['username'], $email]);
                    if ($chk->fetch()) {
                        jsonResponse(['success' => false, 'message' => 'This email is already in use by another account.'], 400);
                    }
                }
                $passwordHash = (string)$existingUser['passwordHash'];
            }

            if ($existingUser && strtolower((string)$existingUser['username']) === strtolower((string)$currentUser['username']) && $status === 'blocked') {
                jsonResponse(['success' => false, 'message' => 'You cannot block your own active administrator account.'], 400);
            }

            $requestDate = (string)($data['requestDate'] ?? ($existingUser['requestDate'] ?? date('n/j/Y, g:i:s A')));
            $canonicalName = $existingUser ? (string)$existingUser['username'] : $targetUsername;

            if ($existingUser) {
                if ($status === 'blocked') {
                    $upd = $pdo->prepare("UPDATE users SET email = ?, passwordHash = ?, role = ?, status = ?, mustResetPassword = ?, requestDate = ?, api_token = NULL, token_expires_at = NULL, lastSeen = 0 WHERE username = ?");
                    $upd->execute([$email, $passwordHash, $role, $status, $mustResetPassword, $requestDate, $canonicalName]);
                } else {
                    $upd = $pdo->prepare("UPDATE users SET email = ?, passwordHash = ?, role = ?, status = ?, mustResetPassword = ?, requestDate = ? WHERE username = ?");
                    $upd->execute([$email, $passwordHash, $role, $status, $mustResetPassword, $requestDate, $canonicalName]);
                }
            } else {
                $ins = $pdo->prepare("INSERT INTO users (username, email, passwordHash, role, status, requestDate, lastSeen, mustResetPassword, api_token, token_expires_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, NULL)");
                $ins->execute([$canonicalName, $email, $passwordHash, $role, $status, $requestDate, $mustResetPassword]);
            }

            bumpDataVersion($pdo);
            $savedUser = findUser($pdo, $canonicalName);

            if ($rawPassword !== '' && $rawPassword !== null && $email !== '') {
                $defaultUrl = (defined('APP_URL') && APP_URL !== '') ? rtrim((string)APP_URL, '/') : detectPortalBaseUrl();
                $portalUrl = sanitizePortalRedirectUrlPhp($data['portalLink'] ?? null, $defaultUrl);
                sendWelcomeEmail($email, $canonicalName, (string)$rawPassword, $portalUrl);
            }

            jsonResponse(['success' => true, 'user' => $savedUser ? formatPublicUserForViewer($savedUser, (string)$currentUser['role'], (string)$currentUser['username']) : null]);
        }

        if ($action === 'delete_user') {
            $target = trim((string)($data['username'] ?? ''));
            if (strtolower($target) === 'admin') {
                jsonResponse(['success' => false, 'message' => 'Cannot delete primary admin account.'], 400);
            }
            if (strtolower($target) === strtolower((string)$currentUser['username'])) {
                jsonResponse(['success' => false, 'message' => 'Cannot delete your own currently logged-in account.'], 400);
            }

            $del = $pdo->prepare("DELETE FROM users WHERE LOWER(username) = LOWER(?)");
            $del->execute([$target]);
            if ($del->rowCount() > 0) {
                bumpDataVersion($pdo);
            }
            jsonResponse(['success' => true]);
        }
    }

    // 11, 12, 13. ASSETS CRUD & BATCH IMPORT
    if (in_array($action, ['save_asset', 'batch_save_assets', 'delete_asset'], true)) {
        if (!in_array($currentUser['role'], ['admin', 'Maintenance'], true)) {
            jsonResponse([
                'success' => false,
                'message' => 'Forbidden: Only Admin and Maintenance can create or modify asset records.'
            ], 403);
        }

        if ($action === 'save_asset') {
            $tag = trim((string)($data['tag'] ?? ''));
            if ($tag === '') {
                jsonResponse(['success' => false, 'message' => 'Asset tag is required.'], 400);
            }

            $stmt = $pdo->prepare("SELECT * FROM assets WHERE LOWER(tag) = LOWER(?) LIMIT 1");
            $stmt->execute([$tag]);
            $existingRow = $stmt->fetch();
            $existingAsset = $existingRow ? formatAssetRow($existingRow) : null;

            if ($existingAsset && $existingAsset['status'] === 'Waiting for Receive' && isset($data['status']) && $data['status'] !== 'Waiting for Receive') {
                jsonResponse([
                    'success' => false,
                    'message' => 'Status locked: Maintenance must click "Received" in Slot Details before changing this asset\'s status.'
                ], 403);
            }

            if ($existingAsset) {
                $type = array_key_exists('type', $data) ? (string)$data['type'] : $existingAsset['type'];
                $brand = array_key_exists('brand', $data) ? (string)$data['brand'] : $existingAsset['brand'];
                $model = array_key_exists('model', $data) ? (string)$data['model'] : $existingAsset['model'];
                $serial = array_key_exists('serial', $data) ? (string)$data['serial'] : $existingAsset['serial'];
                $status = array_key_exists('status', $data) ? (string)$data['status'] : $existingAsset['status'];
                $purchaseDate = array_key_exists('purchaseDate', $data) ? (string)$data['purchaseDate'] : $existingAsset['purchaseDate'];
                $repairCount = array_key_exists('repairCount', $data) ? (int)$data['repairCount'] : $existingAsset['repairCount'];
                $deliveryCount = array_key_exists('deliveryCount', $data) ? (int)$data['deliveryCount'] : $existingAsset['deliveryCount'];
                $repairs = (isset($data['repairs']) && is_array($data['repairs'])) ? $data['repairs'] : $existingAsset['repairs'];
                $warrantyStage = array_key_exists('warranty_stage', $data) ? $data['warranty_stage'] : $existingAsset['warranty_stage'];
                $warrantyIssue = array_key_exists('warranty_issue', $data) ? $data['warranty_issue'] : $existingAsset['warranty_issue'];
                $warrantyVendor = array_key_exists('warranty_vendor', $data) ? $data['warranty_vendor'] : $existingAsset['warranty_vendor'];
                $warrantyReceivedDate = array_key_exists('warranty_received_date', $data) ? $data['warranty_received_date'] : $existingAsset['warranty_received_date'];

                $upd = $pdo->prepare("UPDATE assets SET type=?, brand=?, model=?, serial=?, status=?, purchaseDate=?, repairCount=?, deliveryCount=?, repairs_json=?, warranty_stage=?, warranty_issue=?, warranty_vendor=?, warranty_received_date=? WHERE tag=?");
                $upd->execute([
                    $type, $brand, $model, $serial, $status, $purchaseDate,
                    $repairCount, $deliveryCount, json_encode($repairs, JSON_UNESCAPED_UNICODE),
                    $warrantyStage, $warrantyIssue, $warrantyVendor, $warrantyReceivedDate,
                    $existingAsset['tag']
                ]);
                $savedTag = $existingAsset['tag'];
            } else {
                $repairs = (isset($data['repairs']) && is_array($data['repairs'])) ? $data['repairs'] : [];
                $ins = $pdo->prepare("INSERT INTO assets (tag, type, brand, model, serial, status, purchaseDate, repairCount, deliveryCount, repairs_json, warranty_stage, warranty_issue, warranty_vendor, warranty_received_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $ins->execute([
                    $tag,
                    (string)($data['type'] ?? 'Laptop'),
                    (string)($data['brand'] ?? ''),
                    (string)($data['model'] ?? ''),
                    (string)($data['serial'] ?? ''),
                    (string)($data['status'] ?? 'N/A'),
                    (string)($data['purchaseDate'] ?? ''),
                    (int)($data['repairCount'] ?? 0),
                    (int)($data['deliveryCount'] ?? 0),
                    json_encode($repairs, JSON_UNESCAPED_UNICODE),
                    $data['warranty_stage'] ?? null,
                    $data['warranty_issue'] ?? null,
                    $data['warranty_vendor'] ?? null,
                    $data['warranty_received_date'] ?? null
                ]);
                $savedTag = $tag;
            }

            bumpDataVersion($pdo);
            $stmt = $pdo->prepare("SELECT * FROM assets WHERE tag = ? LIMIT 1");
            $stmt->execute([$savedTag]);
            $savedRow = $stmt->fetch();
            jsonResponse(['success' => true, 'asset' => $savedRow ? formatAssetRow($savedRow) : null]);
        }

        if ($action === 'batch_save_assets') {
            $incoming = is_array($data['assets'] ?? null) ? $data['assets'] : [];
            if (count($incoming) === 0) {
                jsonResponse(['success' => false, 'message' => 'No assets provided for import.'], 400);
            }

            $existingRows = $pdo->query("SELECT tag, serial FROM assets")->fetchAll();
            $existingTags = [];
            $existingSerials = [];
            foreach ($existingRows as $r) {
                $existingTags[strtolower(trim((string)$r['tag']))] = true;
                $ser = strtolower(trim((string)$r['serial']));
                if ($ser !== '') {
                    $existingSerials[$ser] = true;
                }
            }

            $savedCount = 0;
            $skippedCount = 0;

            $pdo->beginTransaction();
            try {
                $ins = $pdo->prepare("INSERT INTO assets (tag, type, brand, model, serial, status, purchaseDate, repairCount, deliveryCount, repairs_json) VALUES (?, ?, ?, ?, ?, 'N/A', ?, 0, 0, '[]')");
                foreach ($incoming as $raw) {
                    if (!is_array($raw)) {
                        $skippedCount += 1;
                        continue;
                    }
                    $tag = trim((string)($raw['tag'] ?? ''));
                    $serial = trim((string)($raw['serial'] ?? ''));
                    if ($tag === '') {
                        $skippedCount += 1;
                        continue;
                    }
                    $tagKey = strtolower($tag);
                    $serialKey = strtolower($serial);
                    if (isset($existingTags[$tagKey]) || ($serialKey !== '' && isset($existingSerials[$serialKey]))) {
                        $skippedCount += 1;
                        continue;
                    }
                    $type = trim((string)($raw['type'] ?? 'Laptop'));
                    if ($type === '') $type = 'Laptop';

                    $ins->execute([
                        $tag,
                        $type,
                        trim((string)($raw['brand'] ?? '')),
                        trim((string)($raw['model'] ?? '')),
                        $serial,
                        trim((string)($raw['purchaseDate'] ?? ''))
                    ]);
                    $existingTags[$tagKey] = true;
                    if ($serialKey !== '') {
                        $existingSerials[$serialKey] = true;
                    }
                    $savedCount += 1;
                }
                if ($savedCount > 0) {
                    bumpDataVersion($pdo);
                }
                $pdo->commit();
            } catch (Throwable $txErr) {
                $pdo->rollBack();
                throw $txErr;
            }

            jsonResponse(['success' => true, 'savedCount' => $savedCount, 'skippedCount' => $skippedCount]);
        }

        if ($action === 'delete_asset') {
            if ($currentUser['role'] !== 'admin') {
                jsonResponse(['success' => false, 'message' => 'Forbidden: Only Administrator can delete asset records.'], 403);
            }
            $tag = trim((string)($data['tag'] ?? ''));
            $del = $pdo->prepare("DELETE FROM assets WHERE LOWER(tag) = LOWER(?)");
            $del->execute([$tag]);
            if ($del->rowCount() > 0) {
                bumpDataVersion($pdo);
            }
            jsonResponse(['success' => true]);
        }
    }

    // 14 & 15. SLOTS CRUD
    if ($action === 'save_slot' || $action === 'delete_slot') {
        if (!in_array($currentUser['role'], ['admin', 'Maintenance', 'IT Support'], true)) {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin, Maintenance, or IT Support can modify slots.'], 403);
        }

        if ($action === 'save_slot') {
            $slotId = isset($data['id']) ? (int)$data['id'] : 0;
            if ($slotId > 0) {
                $stmt = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
                $stmt->execute([$slotId]);
                $currentRow = $stmt->fetch();
                if ($currentRow) {
                    $cur = formatSlotRow($currentRow);
                    $total = array_key_exists('totalAssets', $data) ? (int)$data['totalAssets'] : $cur['totalAssets'];
                    $ret = array_key_exists('returnToIT', $data) ? (int)$data['returnToIT'] : $cur['returnToIT'];
                    $eol = array_key_exists('eol', $data) ? (int)$data['eol'] : $cur['eol'];
                    $pending = (array_key_exists('totalAssets', $data) || array_key_exists('returnToIT', $data) || array_key_exists('eol', $data))
                        ? ($total - $ret - $eol)
                        : $cur['pending'];

                    $upd = $pdo->prepare("UPDATE slots SET sn=?, date_val=?, slotNo=?, slotName=?, totalAssets=?, returnToIT=?, eol=?, pending=?, remarks=?, slotAssets_json=?, slotAccessories_json=?, receivedByMaintenance=?, receivedAt=?, receivedBy=? WHERE id=?");
                    $upd->execute([
                        (string)($data['sn'] ?? $cur['sn']),
                        (string)($data['date_val'] ?? $cur['date_val']),
                        (string)($data['slotNo'] ?? $cur['slotNo']),
                        (string)($data['slotName'] ?? $cur['slotName']),
                        $total,
                        $ret,
                        $eol,
                        $pending,
                        array_key_exists('remarks', $data) ? (string)$data['remarks'] : $cur['remarks'],
                        json_encode(isset($data['slotAssets']) && is_array($data['slotAssets']) ? $data['slotAssets'] : $cur['slotAssets'], JSON_UNESCAPED_UNICODE),
                        json_encode(isset($data['slotAccessories']) && is_array($data['slotAccessories']) ? $data['slotAccessories'] : $cur['slotAccessories'], JSON_UNESCAPED_UNICODE),
                        array_key_exists('receivedByMaintenance', $data) ? ((bool)$data['receivedByMaintenance'] ? 1 : 0) : ($cur['receivedByMaintenance'] ? 1 : 0),
                        array_key_exists('receivedAt', $data) ? $data['receivedAt'] : $cur['receivedAt'],
                        array_key_exists('receivedBy', $data) ? $data['receivedBy'] : $cur['receivedBy'],
                        $slotId
                    ]);
                    bumpDataVersion($pdo);
                    $stmt2 = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
                    $stmt2->execute([$slotId]);
                    $saved = $stmt2->fetch();
                    $formattedSaved = $saved ? formatSlotRow($saved) : null;
                    $syncedProducts = syncAssessmentProductsPhp(
                        $pdo,
                        $formattedSaved ? extractSlotAssessmentProductNamesPhp($formattedSaved['slotAssets'] ?? []) : []
                    );
                    jsonResponse([
                        'success' => true,
                        'slot' => $formattedSaved,
                        'assessmentProducts' => $syncedProducts
                    ]);
                }
            }

            $total = (int)($data['totalAssets'] ?? 0);
            $ret = (int)($data['returnToIT'] ?? 0);
            $eol = (int)($data['eol'] ?? 0);
            $pending = $total - $ret - $eol;
            $dateVal = trim((string)($data['date_val'] ?? '')) ?: date('Y-m-d');
            $slotName = trim((string)($data['slotName'] ?? '')) ?: 'Laptop Repair';

            $ins = $pdo->prepare("INSERT INTO slots (sn, date_val, slotNo, slotName, totalAssets, returnToIT, eol, pending, remarks, slotAssets_json, slotAccessories_json, receivedByMaintenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)");
            $ins->execute([
                (string)($data['sn'] ?? '00'),
                $dateVal,
                (string)($data['slotNo'] ?? ('S-' . time())),
                $slotName,
                $total,
                $ret,
                $eol,
                $pending,
                (string)($data['remarks'] ?? ''),
                json_encode(is_array($data['slotAssets'] ?? null) ? $data['slotAssets'] : [], JSON_UNESCAPED_UNICODE),
                json_encode(is_array($data['slotAccessories'] ?? null) ? $data['slotAccessories'] : [], JSON_UNESCAPED_UNICODE)
            ]);
            $newId = (int)$pdo->lastInsertId();
            bumpDataVersion($pdo);
            $stmt2 = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
            $stmt2->execute([$newId]);
            $saved = $stmt2->fetch();
            $formattedSaved = $saved ? formatSlotRow($saved) : null;
            $syncedProducts = syncAssessmentProductsPhp(
                $pdo,
                $formattedSaved ? extractSlotAssessmentProductNamesPhp($formattedSaved['slotAssets'] ?? []) : []
            );
            jsonResponse([
                'success' => true,
                'slot' => $formattedSaved,
                'assessmentProducts' => $syncedProducts
            ]);
        }

        if ($action === 'delete_slot') {
            $slotId = (int)($data['id'] ?? 0);
            $del = $pdo->prepare("DELETE FROM slots WHERE id = ?");
            $del->execute([$slotId]);
            if ($del->rowCount() > 0) {
                bumpDataVersion($pdo);
            }
            jsonResponse(['success' => true]);
        }
    }

    // 16. ADD SLOT DEVICE
    if ($action === 'add_slot_device') {
        if (!in_array($currentUser['role'], ['admin', 'IT Support'], true)) {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin and IT Support can add devices to a slot.'], 403);
        }

        $slotId = (int)($data['slotId'] ?? 0);
        $tag = trim((string)($data['tag'] ?? ''));
        $issue = trim((string)($data['issue'] ?? ''));

        if (!$slotId || $tag === '' || $issue === '') {
            jsonResponse(['success' => false, 'message' => 'Slot ID, Asset Tag, and Asset Issue are required.'], 400);
        }

        $slotStmt = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
        $slotStmt->execute([$slotId]);
        $slotRow = $slotStmt->fetch();
        if (!$slotRow) {
            jsonResponse(['success' => false, 'message' => 'Slot record not found.'], 404);
        }
        $slot = formatSlotRow($slotRow);

        $assetStmt = $pdo->prepare("SELECT * FROM assets WHERE LOWER(tag) = LOWER(?) LIMIT 1");
        $assetStmt->execute([$tag]);
        $assetRow = $assetStmt->fetch();
        if (!$assetRow) {
            jsonResponse(['success' => false, 'message' => "Asset Tag \"$tag\" was not found in the database."], 404);
        }
        $asset = formatAssetRow($assetRow);

        if ($asset['status'] === 'In warranty') {
            jsonResponse(['success' => false, 'message' => "Asset \"{$asset['tag']}\" is currently in Warranty and cannot be added to a repair slot."], 400);
        }

        $existingEntries = $slot['slotAssets'] ?? [];
        foreach ($existingEntries as $entry) {
            if (strtolower((string)($entry['tag'] ?? '')) === strtolower($asset['tag'])) {
                jsonResponse(['success' => false, 'message' => "Asset \"{$asset['tag']}\" is already added to this slot."], 400);
            }
        }

        $newEntry = [
            'id' => nowMs() . '-' . bin2hex(random_bytes(3)),
            'tag' => $asset['tag'],
            'serial' => $asset['serial'] ?: 'N/A',
            'brand' => $asset['brand'] ?: '',
            'model' => $asset['model'] ?: '',
            'purchaseDate' => $asset['purchaseDate'] ?: 'N/A',
            'issue' => $issue,
            'recommendations' => [],
            'remarks' => ''
        ];

        $existingEntries[] = $newEntry;

        $pdo->prepare("UPDATE assets SET status = 'Waiting for Receive' WHERE tag = ?")->execute([$asset['tag']]);
        $pdo->prepare("UPDATE slots SET slotAssets_json = ?, receivedByMaintenance = 0 WHERE id = ?")->execute([
            json_encode($existingEntries, JSON_UNESCAPED_UNICODE),
            $slot['id']
        ]);

        bumpDataVersion($pdo);

        $slotStmt->execute([$slot['id']]);
        $assetStmt->execute([$asset['tag']]);
        jsonResponse([
            'success' => true,
            'slot' => formatSlotRow($slotStmt->fetch()),
            'asset' => formatAssetRow($assetStmt->fetch())
        ]);
    }

    // 17. UPDATE SLOT ASSESSMENT
    if ($action === 'update_slot_assessment') {
        if ($currentUser['role'] !== 'Maintenance') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Maintenance role users can edit assessments, recommendations, and accessories.'], 403);
        }

        $slotId = (int)($data['slotId'] ?? 0);
        $slotStmt = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
        $slotStmt->execute([$slotId]);
        $slotRow = $slotStmt->fetch();
        if (!$slotRow) {
            jsonResponse(['success' => false, 'message' => 'Slot record not found.'], 404);
        }
        $slot = formatSlotRow($slotRow);

        $incomingAssets = is_array($data['slotAssets'] ?? null) ? $data['slotAssets'] : $slot['slotAssets'];
        $existingById = [];
        foreach ($slot['slotAssets'] as $orig) {
            if (!empty($orig['id'])) {
                $existingById[$orig['id']] = $orig;
            }
        }

        $sanitizedAssets = [];
        foreach ($incomingAssets as $entry) {
            if (!is_array($entry)) continue;
            $orig = isset($entry['id'], $existingById[$entry['id']]) ? $existingById[$entry['id']] : null;
            $recs = [];
            if (is_array($entry['recommendations'] ?? null)) {
                foreach ($entry['recommendations'] as $r) {
                    $cleanRec = trim((string)$r);
                    if ($cleanRec !== '') $recs[] = $cleanRec;
                }
            } elseif ($orig && is_array($orig['recommendations'] ?? null)) {
                $recs = $orig['recommendations'];
            }

            $sanitizedAssets[] = [
                'id' => $orig['id'] ?? ($entry['id'] ?? ''),
                'tag' => $orig['tag'] ?? ($entry['tag'] ?? ''),
                'serial' => $orig['serial'] ?? ($entry['serial'] ?? ''),
                'brand' => $orig['brand'] ?? ($entry['brand'] ?? ''),
                'model' => $orig['model'] ?? ($entry['model'] ?? ''),
                'purchaseDate' => $orig['purchaseDate'] ?? ($entry['purchaseDate'] ?? ''),
                'issue' => $orig['issue'] ?? ($entry['issue'] ?? ''),
                'recommendations' => $recs,
                'remarks' => isset($entry['remarks']) ? (string)$entry['remarks'] : ($orig['remarks'] ?? '')
            ];
        }

        $incomingAccessories = is_array($data['slotAccessories'] ?? null) ? $data['slotAccessories'] : $slot['slotAccessories'];
        $computedAccessories = aggregateSlotAccessoriesPhp($sanitizedAssets, $incomingAccessories);

        $pdo->prepare("UPDATE slots SET slotAssets_json = ?, slotAccessories_json = ? WHERE id = ?")->execute([
            json_encode($sanitizedAssets, JSON_UNESCAPED_UNICODE),
            json_encode($computedAccessories, JSON_UNESCAPED_UNICODE),
            $slot['id']
        ]);

        $recommendedProducts = extractSlotAssessmentProductNamesPhp($sanitizedAssets);
        $assessmentProducts = syncAssessmentProductsPhp($pdo, $recommendedProducts);

        bumpDataVersion($pdo);
        $slotStmt->execute([$slot['id']]);
        jsonResponse([
            'success' => true,
            'slot' => formatSlotRow($slotStmt->fetch()),
            'assessmentProducts' => $assessmentProducts
        ]);
    }

    // 18. RECEIVE SLOT
    if ($action === 'receive_slot') {
        if ($currentUser['role'] !== 'Maintenance') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Maintenance role users can mark a slot as Received.'], 403);
        }

        $slotId = (int)($data['slotId'] ?? 0);
        $slotStmt = $pdo->prepare("SELECT * FROM slots WHERE id = ? LIMIT 1");
        $slotStmt->execute([$slotId]);
        $slotRow = $slotStmt->fetch();
        if (!$slotRow) {
            jsonResponse(['success' => false, 'message' => 'Slot record not found.'], 404);
        }
        $slot = formatSlotRow($slotRow);
        $slotAssets = $slot['slotAssets'] ?? [];

        if (count($slotAssets) === 0) {
            jsonResponse(['success' => false, 'message' => 'No assets have been added to this slot yet.'], 400);
        }

        $updatedCount = 0;
        $updAsset = $pdo->prepare("UPDATE assets SET status = 'Received for Repair' WHERE LOWER(tag) = LOWER(?) AND status = 'Waiting for Receive'");
        foreach ($slotAssets as $entry) {
            if (empty($entry['tag'])) continue;
            $updAsset->execute([(string)$entry['tag']]);
            $updatedCount += $updAsset->rowCount();
        }

        $receivedAt = gmdate('Y-m-d\TH:i:s.v\Z');
        $pdo->prepare("UPDATE slots SET receivedByMaintenance = 1, receivedAt = ?, receivedBy = ? WHERE id = ?")->execute([
            $receivedAt,
            $currentUser['username'],
            $slot['id']
        ]);

        bumpDataVersion($pdo);
        $slotStmt->execute([$slot['id']]);
        jsonResponse(['success' => true, 'slot' => formatSlotRow($slotStmt->fetch()), 'updatedCount' => $updatedCount]);
    }

    // 19. VENDORS CRUD
    if ($action === 'save_vendor') {
        if ($currentUser['role'] !== 'admin') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin can add vendors.'], 403);
        }
        $vendorName = trim((string)($data['vendorName'] ?? ''));
        $companyName = trim((string)($data['companyName'] ?? ''));
        $phone = trim((string)($data['phone'] ?? ''));
        $email = trim((string)($data['email'] ?? ''));

        if ($vendorName === '' || $companyName === '' || $phone === '' || $email === '') {
            jsonResponse(['success' => false, 'message' => 'Vendor name, company name, phone number, and email address are required.'], 400);
        }

        $dup = $pdo->prepare("SELECT id FROM vendors WHERE LOWER(companyName) = LOWER(?) LIMIT 1");
        $dup->execute([$companyName]);
        if ($dup->fetch()) {
            jsonResponse(['success' => false, 'message' => "Vendor company \"$companyName\" is already registered."], 400);
        }

        $createdAt = gmdate('Y-m-d\TH:i:s.v\Z');
        $ins = $pdo->prepare("INSERT INTO vendors (vendorName, companyName, phone, email, createdAt) VALUES (?, ?, ?, ?, ?)");
        $ins->execute([$vendorName, $companyName, $phone, $email, $createdAt]);
        $newId = (int)$pdo->lastInsertId();
        bumpDataVersion($pdo);

        $stmt = $pdo->prepare("SELECT * FROM vendors WHERE id = ? LIMIT 1");
        $stmt->execute([$newId]);
        jsonResponse(['success' => true, 'vendor' => formatVendorRow($stmt->fetch())]);
    }

    if ($action === 'delete_vendor') {
        if ($currentUser['role'] !== 'admin') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin can delete vendors.'], 403);
        }
        $vendorId = (int)($data['id'] ?? 0);
        if (!$vendorId) {
            jsonResponse(['success' => false, 'message' => 'Vendor ID is required.'], 400);
        }
        $del = $pdo->prepare("DELETE FROM vendors WHERE id = ?");
        $del->execute([$vendorId]);
        if ($del->rowCount() === 0) {
            jsonResponse(['success' => false, 'message' => 'Vendor record not found.'], 404);
        }
        bumpDataVersion($pdo);
        jsonResponse(['success' => true]);
    }

    // 20. ASSESSMENT PRODUCTS CATALOG
    if ($action === 'import_assessment_products') {
        if (!in_array($currentUser['role'], ['admin', 'Maintenance'], true)) {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin and Maintenance can import slot assessment products.'], 403);
        }

        $rawProducts = is_array($data['products'] ?? null) ? $data['products'] : [];
        $cleanedProducts = array_values(array_filter(array_map(fn($p) => trim((string)$p), $rawProducts), fn($p) => $p !== ''));

        if (count($cleanedProducts) === 0) {
            jsonResponse(['success' => false, 'message' => 'Please provide at least one valid product name to import.'], 400);
        }

        $existingRows = $pdo->query("SELECT productName FROM assessment_products")->fetchAll();
        $existingKeys = [];
        foreach ($existingRows as $r) {
            $existingKeys[strtolower(trim((string)$r['productName']))] = true;
        }

        $addedCount = 0;
        $ins = $pdo->prepare("INSERT INTO assessment_products (productName) VALUES (?)");
        foreach ($cleanedProducts as $prod) {
            $k = strtolower($prod);
            if (!isset($existingKeys[$k])) {
                $ins->execute([$prod]);
                $existingKeys[$k] = true;
                $addedCount += 1;
            }
        }

        if ($addedCount > 0) {
            bumpDataVersion($pdo);
        }

        $prodRows = $pdo->query("SELECT productName FROM assessment_products ORDER BY productName ASC")->fetchAll();
        $products = array_map(fn($r) => (string)$r['productName'], $prodRows);

        jsonResponse(['success' => true, 'assessmentProducts' => $products, 'addedCount' => $addedCount]);
    }

    if ($action === 'delete_assessment_product') {
        if (!in_array($currentUser['role'], ['admin', 'Maintenance'], true)) {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Only Admin and Maintenance can remove slot assessment products.'], 403);
        }
        $product = trim((string)($data['product'] ?? ''));
        if ($product === '') {
            jsonResponse(['success' => false, 'message' => 'Product name is required.'], 400);
        }
        $del = $pdo->prepare("DELETE FROM assessment_products WHERE LOWER(productName) = LOWER(?)");
        $del->execute([$product]);
        if ($del->rowCount() > 0) {
            bumpDataVersion($pdo);
        }
        $prodRows = $pdo->query("SELECT productName FROM assessment_products ORDER BY productName ASC")->fetchAll();
        $products = array_map(fn($r) => (string)$r['productName'], $prodRows);
        jsonResponse(['success' => true, 'assessmentProducts' => $products]);
    }

    // 21. EXPORT SQL BACKUP (ADMIN ONLY)
    if ($action === 'export_sql') {
        if ($currentUser['role'] !== 'admin') {
            jsonResponse(['success' => false, 'message' => 'Forbidden: Admin role required to export database backup.'], 403);
        }

        $users = $pdo->query("SELECT * FROM users")->fetchAll();
        $slots = $pdo->query("SELECT * FROM slots ORDER BY id DESC")->fetchAll();
        $assets = $pdo->query("SELECT * FROM assets")->fetchAll();
        $vendors = $pdo->query("SELECT * FROM vendors ORDER BY id ASC")->fetchAll();
        $prodRows = $pdo->query("SELECT productName FROM assessment_products ORDER BY productName ASC")->fetchAll();

        $sqlDump = "-- AssetCare Enterprise SQL Dump\n-- Generated on: " . gmdate('Y-m-d\TH:i:s\Z') . "\n\n";
        $sqlDump .= "SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n";
        $sqlDump .= "SET FOREIGN_KEY_CHECKS = 0;\n\n";
        $sqlDump .= "TRUNCATE TABLE `users`;\n";
        foreach ($users as $u) {
            $sqlDump .= sprintf(
                "INSERT INTO `users` (`username`, `email`, `passwordHash`, `role`, `status`, `requestDate`, `lastSeen`, `mustResetPassword`) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', %d, %d);\n",
                sqlEscape((string)($u['username'] ?? '')),
                sqlEscape((string)($u['email'] ?? '')),
                sqlEscape((string)($u['passwordHash'] ?? '')),
                sqlEscape(normalizeUserRolePhp((string)($u['role'] ?? 'Maintenance'))),
                sqlEscape(normalizeUserStatusPhp((string)($u['status'] ?? 'active'))),
                sqlEscape((string)($u['requestDate'] ?? '')),
                (int)($u['lastSeen'] ?? 0),
                (int)($u['mustResetPassword'] ?? 0)
            );
        }

        $sqlDump .= "\nTRUNCATE TABLE `slots`;\n";
        foreach ($slots as $s) {
            $recAt = isset($s['receivedAt']) && $s['receivedAt'] !== null ? ("'" . sqlEscape((string)$s['receivedAt']) . "'") : 'NULL';
            $recBy = isset($s['receivedBy']) && $s['receivedBy'] !== null ? ("'" . sqlEscape((string)$s['receivedBy']) . "'") : 'NULL';
            $sqlDump .= sprintf(
                "INSERT INTO `slots` (`id`, `sn`, `date_val`, `slotNo`, `slotName`, `totalAssets`, `returnToIT`, `eol`, `pending`, `remarks`, `slotAssets_json`, `slotAccessories_json`, `receivedByMaintenance`, `receivedAt`, `receivedBy`) VALUES (%d, '%s', '%s', '%s', '%s', %d, %d, %d, %d, '%s', '%s', '%s', %d, %s, %s);\n",
                (int)($s['id'] ?? 0),
                sqlEscape((string)($s['sn'] ?? '')),
                sqlEscape((string)($s['date_val'] ?? '')),
                sqlEscape((string)($s['slotNo'] ?? '')),
                sqlEscape((string)($s['slotName'] ?? 'Laptop Repair')),
                (int)($s['totalAssets'] ?? 0),
                (int)($s['returnToIT'] ?? 0),
                (int)($s['eol'] ?? 0),
                (int)($s['pending'] ?? 0),
                sqlEscape((string)($s['remarks'] ?? '')),
                sqlEscape((string)($s['slotAssets_json'] ?? '[]')),
                sqlEscape((string)($s['slotAccessories_json'] ?? '[]')),
                (int)($s['receivedByMaintenance'] ?? 0),
                $recAt,
                $recBy
            );
        }

        $sqlDump .= "\nTRUNCATE TABLE `assets`;\n";
        foreach ($assets as $a) {
            $stageVal = isset($a['warranty_stage']) && $a['warranty_stage'] !== null ? ("'" . sqlEscape((string)$a['warranty_stage']) . "'") : 'NULL';
            $issueVal = isset($a['warranty_issue']) && $a['warranty_issue'] !== null ? ("'" . sqlEscape((string)$a['warranty_issue']) . "'") : 'NULL';
            $vendorVal = isset($a['warranty_vendor']) && $a['warranty_vendor'] !== null ? ("'" . sqlEscape((string)$a['warranty_vendor']) . "'") : 'NULL';
            $recDateVal = isset($a['warranty_received_date']) && $a['warranty_received_date'] !== null ? ("'" . sqlEscape((string)$a['warranty_received_date']) . "'") : 'NULL';
            $sqlDump .= sprintf(
                "INSERT INTO `assets` (`tag`, `type`, `brand`, `model`, `serial`, `status`, `purchaseDate`, `repairCount`, `deliveryCount`, `repairs_json`, `warranty_stage`, `warranty_issue`, `warranty_vendor`, `warranty_received_date`) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, '%s', %s, %s, %s, %s);\n",
                sqlEscape((string)($a['tag'] ?? '')),
                sqlEscape((string)($a['type'] ?? 'Laptop')),
                sqlEscape((string)($a['brand'] ?? '')),
                sqlEscape((string)($a['model'] ?? '')),
                sqlEscape((string)($a['serial'] ?? '')),
                sqlEscape((string)($a['status'] ?? 'N/A')),
                sqlEscape((string)($a['purchaseDate'] ?? '')),
                (int)($a['repairCount'] ?? 0),
                (int)($a['deliveryCount'] ?? 0),
                sqlEscape((string)($a['repairs_json'] ?? '[]')),
                $stageVal,
                $issueVal,
                $vendorVal,
                $recDateVal
            );
        }

        $sqlDump .= "\nTRUNCATE TABLE `vendors`;\n";
        foreach ($vendors as $v) {
            $sqlDump .= sprintf(
                "INSERT INTO `vendors` (`id`, `vendorName`, `companyName`, `phone`, `email`, `createdAt`) VALUES (%d, '%s', '%s', '%s', '%s', '%s');\n",
                (int)($v['id'] ?? 0),
                sqlEscape((string)($v['vendorName'] ?? '')),
                sqlEscape((string)($v['companyName'] ?? '')),
                sqlEscape((string)($v['phone'] ?? '')),
                sqlEscape((string)($v['email'] ?? '')),
                sqlEscape((string)($v['createdAt'] ?? ''))
            );
        }

        $sqlDump .= "\nTRUNCATE TABLE `assessment_products`;\n";
        foreach ($prodRows as $pr) {
            $sqlDump .= sprintf(
                "INSERT IGNORE INTO `assessment_products` (`productName`) VALUES ('%s');\n",
                sqlEscape((string)($pr['productName'] ?? ''))
            );
        }

        $sqlDump .= "\nSET FOREIGN_KEY_CHECKS = 1;\n";

        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        header('Content-Type: application/sql; charset=UTF-8');
        header('Content-Disposition: attachment; filename="assetcare_backup_' . date('Y-m-d') . '.sql"');
        echo $sqlDump;
        exit;
    }

    jsonResponse(['success' => false, 'message' => 'Unknown API action.'], 404);
} catch (Throwable $e) {
    error_log('[AssetCare API Error] ' . $e->getMessage());
    jsonResponse(['success' => false, 'message' => 'Internal server error while processing request.'], 500);
}
