<?php
// Built by Abdur Rahman
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function getDbConnection(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=%s',
        DB_HOST,
        DB_PORT,
        DB_NAME,
        DB_CHARSET
    );

    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 5
    ]);

    ensureSchema($pdo);
    return $pdo;
}

function ensureSchema(PDO $pdo): void {
    static $checked = false;
    if ($checked) {
        return;
    }
    $checked = true;

    $requiredTables = [
        'users',
        'assets',
        'slots',
        'vendors',
        'assessment_products',
        'system_meta',
        'auth_rate_limits',
        'password_reset_sessions'
    ];

    try {
        $existingTables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
        if (is_array($existingTables)) {
            $lowerTables = array_map(fn($t) => strtolower((string)$t), $existingTables);
            $allPresent = true;
            foreach ($requiredTables as $tbl) {
                if (!in_array($tbl, $lowerTables, true)) {
                    $allPresent = false;
                    break;
                }
            }
            if ($allPresent) {
                $colCheck = $pdo->query("SHOW COLUMNS FROM `users` LIKE 'token_expires_at'");
                if ($colCheck !== false && $colCheck->fetch() === false) {
                    $pdo->exec("ALTER TABLE `users` ADD COLUMN `token_expires_at` BIGINT NULL DEFAULT NULL");
                }
                $stmt = $pdo->query("SELECT meta_value FROM system_meta WHERE meta_key = 'data_version' LIMIT 1");
                if ($stmt !== false && $stmt->fetchColumn() !== false) {
                    return;
                }
            }
        }
    } catch (Throwable $e) {
        // Table missing or uninitialized: create full schema below
    }

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `users` (
            `username` VARCHAR(100) NOT NULL,
            `email` VARCHAR(191) NOT NULL DEFAULT '',
            `passwordHash` VARCHAR(255) NOT NULL DEFAULT '',
            `role` ENUM('admin','Maintenance','IT Support','Management') NOT NULL DEFAULT 'Maintenance',
            `status` ENUM('active','blocked','pending') NOT NULL DEFAULT 'active',
            `requestDate` VARCHAR(100) NOT NULL DEFAULT '',
            `lastSeen` BIGINT NOT NULL DEFAULT 0,
            `mustResetPassword` TINYINT(1) NOT NULL DEFAULT 1,
            `reset_code` VARCHAR(255) NULL DEFAULT NULL,
            `reset_expires` VARCHAR(64) NULL DEFAULT NULL,
            `api_token` VARCHAR(128) NULL DEFAULT NULL,
            `token_expires_at` BIGINT NULL DEFAULT NULL,
            PRIMARY KEY (`username`),
            INDEX `idx_users_token` (`api_token`),
            INDEX `idx_users_email` (`email`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `assets` (
            `tag` VARCHAR(100) NOT NULL,
            `type` VARCHAR(100) NOT NULL DEFAULT 'Laptop',
            `brand` VARCHAR(100) NOT NULL DEFAULT '',
            `model` VARCHAR(150) NOT NULL DEFAULT '',
            `serial` VARCHAR(150) NOT NULL DEFAULT '',
            `status` VARCHAR(80) NOT NULL DEFAULT 'N/A',
            `purchaseDate` VARCHAR(64) NOT NULL DEFAULT '',
            `repairCount` INT NOT NULL DEFAULT 0,
            `deliveryCount` INT NOT NULL DEFAULT 0,
            `repairs_json` LONGTEXT NULL,
            `warranty_stage` VARCHAR(150) NULL DEFAULT NULL,
            `warranty_issue` TEXT NULL DEFAULT NULL,
            `warranty_vendor` VARCHAR(150) NULL DEFAULT NULL,
            `warranty_received_date` VARCHAR(64) NULL DEFAULT NULL,
            PRIMARY KEY (`tag`),
            INDEX `idx_assets_serial` (`serial`),
            INDEX `idx_assets_status` (`status`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `slots` (
            `id` INT NOT NULL AUTO_INCREMENT,
            `sn` VARCHAR(50) NOT NULL DEFAULT '',
            `date_val` VARCHAR(64) NOT NULL DEFAULT '',
            `slotNo` VARCHAR(100) NOT NULL DEFAULT '',
            `slotName` VARCHAR(150) NOT NULL DEFAULT 'Laptop Repair',
            `totalAssets` INT NOT NULL DEFAULT 0,
            `returnToIT` INT NOT NULL DEFAULT 0,
            `eol` INT NOT NULL DEFAULT 0,
            `pending` INT NOT NULL DEFAULT 0,
            `remarks` TEXT NULL,
            `slotAssets_json` LONGTEXT NULL,
            `slotAccessories_json` LONGTEXT NULL,
            `receivedByMaintenance` TINYINT(1) NOT NULL DEFAULT 0,
            `receivedAt` VARCHAR(64) NULL DEFAULT NULL,
            `receivedBy` VARCHAR(100) NULL DEFAULT NULL,
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `vendors` (
            `id` INT NOT NULL AUTO_INCREMENT,
            `vendorName` VARCHAR(150) NOT NULL DEFAULT '',
            `companyName` VARCHAR(191) NOT NULL DEFAULT '',
            `phone` VARCHAR(64) NOT NULL DEFAULT '',
            `email` VARCHAR(191) NOT NULL DEFAULT '',
            `createdAt` VARCHAR(64) NOT NULL DEFAULT '',
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `assessment_products` (
            `productName` VARCHAR(191) NOT NULL,
            PRIMARY KEY (`productName`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `system_meta` (
            `meta_key` VARCHAR(100) NOT NULL,
            `meta_value` TEXT NULL,
            PRIMARY KEY (`meta_key`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `auth_rate_limits` (
            `rate_key` VARCHAR(191) NOT NULL,
            `attempts` INT NOT NULL DEFAULT 0,
            `last_attempt` BIGINT NOT NULL DEFAULT 0,
            `blocked_until` BIGINT NULL DEFAULT NULL,
            PRIMARY KEY (`rate_key`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS `password_reset_sessions` (
            `token` VARCHAR(128) NOT NULL,
            `username` VARCHAR(100) NOT NULL,
            `expires_at` BIGINT NOT NULL,
            PRIMARY KEY (`token`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("INSERT IGNORE INTO `system_meta` (`meta_key`, `meta_value`) VALUES ('data_version', '1')");
}

function nowMs(): int {
    return (int)round(microtime(true) * 1000);
}

function normalizeUserRolePhp(?string $role): string {
    $clean = trim((string)($role ?? ''));
    $lower = strtolower($clean);
    if ($lower === 'admin' || $lower === 'administrator') return 'admin';
    if ($lower === 'maintenance') return 'Maintenance';
    if ($lower === 'it support' || $lower === 'it_support' || $lower === 'itsupport') return 'IT Support';
    if ($lower === 'management') return 'Management';
    return $clean !== '' ? $clean : 'Maintenance';
}

function normalizeUserStatusPhp(?string $status): string {
    $clean = strtolower(trim((string)($status ?? '')));
    if (in_array($clean, ['active', 'blocked', 'pending'], true)) {
        return $clean;
    }
    return $clean !== '' ? $clean : 'active';
}

function getDataVersion(PDO $pdo): int {
    $stmt = $pdo->prepare("SELECT meta_value FROM system_meta WHERE meta_key = 'data_version' LIMIT 1");
    $stmt->execute();
    $val = $stmt->fetchColumn();
    if ($val === false) {
        $pdo->exec("INSERT IGNORE INTO system_meta (meta_key, meta_value) VALUES ('data_version', '1')");
        return 1;
    }
    return max(1, (int)$val);
}

function bumpDataVersion(PDO $pdo): int {
    $pdo->exec("INSERT INTO system_meta (meta_key, meta_value) VALUES ('data_version', '2') ON DUPLICATE KEY UPDATE meta_value = CAST(CAST(COALESCE(NULLIF(meta_value, ''), '1') AS UNSIGNED) + 1 AS CHAR)");
    return getDataVersion($pdo);
}

function findUser(PDO $pdo, string $username): ?array {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE LOWER(TRIM(username)) = LOWER(?) LIMIT 1");
    $stmt->execute([trim($username)]);
    $row = $stmt->fetch();
    if ($row === false) {
        return null;
    }
    $row['role'] = normalizeUserRolePhp((string)($row['role'] ?? 'Maintenance'));
    $row['status'] = normalizeUserStatusPhp((string)($row['status'] ?? 'active'));
    return $row;
}

function findUserByToken(PDO $pdo, string $token): ?array {
    if ($token === '') {
        return null;
    }
    $stmt = $pdo->prepare("SELECT * FROM users WHERE api_token = ? LIMIT 1");
    $stmt->execute([$token]);
    $row = $stmt->fetch();
    if ($row === false || empty($row['api_token']) || !hash_equals((string)$row['api_token'], $token)) {
        return null;
    }
    $row['role'] = normalizeUserRolePhp((string)($row['role'] ?? 'Maintenance'));
    $row['status'] = normalizeUserStatusPhp((string)($row['status'] ?? 'active'));
    return $row;
}

function formatPublicUser(array $row): array {
    return [
        'username' => (string)($row['username'] ?? ''),
        'email' => (string)($row['email'] ?? ''),
        'role' => normalizeUserRolePhp((string)($row['role'] ?? 'Maintenance')),
        'status' => normalizeUserStatusPhp((string)($row['status'] ?? 'active')),
        'requestDate' => (string)($row['requestDate'] ?? ''),
        'lastSeen' => (int)($row['lastSeen'] ?? 0),
        'mustResetPassword' => (int)($row['mustResetPassword'] ?? 0)
    ];
}

function formatPublicUserForViewer(array $row, string $viewerRole = 'admin', string $viewerUsername = ''): array {
    $isAdmin = $viewerRole === 'admin';
    $isSelf = $viewerUsername !== '' && strtolower(trim($viewerUsername)) === strtolower(trim((string)($row['username'] ?? '')));
    return [
        'username' => (string)($row['username'] ?? ''),
        'email' => ($isAdmin || $isSelf) ? (string)($row['email'] ?? '') : '',
        'role' => normalizeUserRolePhp((string)($row['role'] ?? 'Maintenance')),
        'status' => normalizeUserStatusPhp((string)($row['status'] ?? 'active')),
        'requestDate' => $isAdmin ? (string)($row['requestDate'] ?? '') : '',
        'lastSeen' => (int)($row['lastSeen'] ?? 0),
        'mustResetPassword' => (int)($row['mustResetPassword'] ?? 0)
    ];
}

function formatAssetRow(array $row): array {
    $repairsRaw = trim((string)($row['repairs_json'] ?? '[]'));
    $repairs = $repairsRaw !== '' ? json_decode($repairsRaw, true) : [];
    if (!is_array($repairs)) {
        $repairs = [];
    }
    return [
        'tag' => (string)($row['tag'] ?? ''),
        'type' => (string)($row['type'] ?? 'Laptop'),
        'brand' => (string)($row['brand'] ?? ''),
        'model' => (string)($row['model'] ?? ''),
        'serial' => (string)($row['serial'] ?? ''),
        'status' => (string)($row['status'] ?? 'N/A'),
        'purchaseDate' => (string)($row['purchaseDate'] ?? ''),
        'repairCount' => (int)($row['repairCount'] ?? 0),
        'deliveryCount' => (int)($row['deliveryCount'] ?? 0),
        'repairs' => $repairs,
        'warranty_stage' => isset($row['warranty_stage']) && $row['warranty_stage'] !== null ? (string)$row['warranty_stage'] : null,
        'warranty_issue' => isset($row['warranty_issue']) && $row['warranty_issue'] !== null ? (string)$row['warranty_issue'] : null,
        'warranty_vendor' => isset($row['warranty_vendor']) && $row['warranty_vendor'] !== null ? (string)$row['warranty_vendor'] : null,
        'warranty_received_date' => isset($row['warranty_received_date']) && $row['warranty_received_date'] !== null ? (string)$row['warranty_received_date'] : null
    ];
}

function formatSlotRow(array $row): array {
    $slotAssetsRaw = trim((string)($row['slotAssets_json'] ?? '[]'));
    $slotAssets = $slotAssetsRaw !== '' ? json_decode($slotAssetsRaw, true) : [];
    if (!is_array($slotAssets)) {
        $slotAssets = [];
    }
    $slotAccessoriesRaw = trim((string)($row['slotAccessories_json'] ?? '[]'));
    $slotAccessories = $slotAccessoriesRaw !== '' ? json_decode($slotAccessoriesRaw, true) : [];
    if (!is_array($slotAccessories)) {
        $slotAccessories = [];
    }
    return [
        'id' => (int)($row['id'] ?? 0),
        'sn' => (string)($row['sn'] ?? ''),
        'date_val' => (string)($row['date_val'] ?? ''),
        'slotNo' => (string)($row['slotNo'] ?? ''),
        'slotName' => (string)($row['slotName'] ?? 'Laptop Repair'),
        'totalAssets' => (int)($row['totalAssets'] ?? 0),
        'returnToIT' => (int)($row['returnToIT'] ?? 0),
        'eol' => (int)($row['eol'] ?? 0),
        'pending' => (int)($row['pending'] ?? 0),
        'remarks' => (string)($row['remarks'] ?? ''),
        'slotAssets' => $slotAssets,
        'slotAccessories' => $slotAccessories,
        'receivedByMaintenance' => (bool)((int)($row['receivedByMaintenance'] ?? 0)),
        'receivedAt' => isset($row['receivedAt']) && $row['receivedAt'] !== null ? (string)$row['receivedAt'] : null,
        'receivedBy' => isset($row['receivedBy']) && $row['receivedBy'] !== null ? (string)$row['receivedBy'] : null
    ];
}

function formatVendorRow(array $row): array {
    return [
        'id' => (int)($row['id'] ?? 0),
        'vendorName' => (string)($row['vendorName'] ?? ''),
        'companyName' => (string)($row['companyName'] ?? ''),
        'phone' => (string)($row['phone'] ?? ''),
        'email' => (string)($row['email'] ?? ''),
        'createdAt' => (string)($row['createdAt'] ?? '')
    ];
}

function extractSlotAssessmentProductNamesPhp(array $slotAssets): array {
    $map = [];
    foreach ($slotAssets as $entry) {
        if (!is_array($entry)) continue;
        $recs = is_array($entry['recommendations'] ?? null) ? $entry['recommendations'] : [];
        foreach ($recs as $rec) {
            $cleaned = trim((string)$rec);
            if ($cleaned === '') continue;
            $key = strtolower($cleaned);
            if (!isset($map[$key])) {
                $map[$key] = $cleaned;
            }
        }
    }
    return array_values($map);
}

function syncAssessmentProductsPhp(PDO $pdo, array $productNames): array {
    $cleaned = [];
    foreach ($productNames as $raw) {
        $name = trim((string)$raw);
        if ($name !== '') {
            $key = strtolower($name);
            if (!isset($cleaned[$key])) {
                $cleaned[$key] = $name;
            }
        }
    }

    if (count($cleaned) > 0) {
        $existingRows = $pdo->query("SELECT productName FROM assessment_products")->fetchAll();
        $existingKeys = [];
        foreach ($existingRows as $r) {
            $existingKeys[strtolower(trim((string)($r['productName'] ?? '')))] = true;
        }

        $ins = $pdo->prepare("INSERT IGNORE INTO assessment_products (productName) VALUES (?)");
        foreach ($cleaned as $k => $name) {
            if (!isset($existingKeys[$k])) {
                $ins->execute([$name]);
                $existingKeys[$k] = true;
            }
        }
    }

    $prodRows = $pdo->query("SELECT productName FROM assessment_products ORDER BY productName ASC")->fetchAll();
    return array_map(fn($r) => (string)($r['productName'] ?? ''), $prodRows);
}


