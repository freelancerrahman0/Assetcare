<?php
// Built by Abdur Rahman
// CENTRALIZED PORTAL CONFIGURATION (XAMPP <-> LIVE SERVER)
// Copy this file to "config.local.php" in the same folder as api.php and edit ONLY that file.
// NEVER share or commit config.local.php publicly. It is blocked from HTTP download by .htaccess.
declare(strict_types=1);

// 1. Choose active environment: 'xampp' (local PC) OR 'live' (production web server)
define('PORTAL_ENV', 'xampp');

// 2. Central settings for XAMPP and Live Server — update this ONE file when deploying:
$PORTAL_ENVIRONMENTS = [
    'xampp' => [
        'DB_HOST'         => '127.0.0.1',
        'DB_PORT'         => 3306,
        'DB_NAME'         => 'assetcare_db',
        'DB_USER'         => 'root',
        'DB_PASS'         => '',
        'SMTP_HOST'       => 'smtp.gmail.com',
        'SMTP_PORT'       => 587,
        'SMTP_USER'       => 'your-email@quantanite.com',
        'SMTP_PASS'       => '',
        'SMTP_FROM_NAME'  => 'AssetCare',
        'APP_URL'         => 'http://localhost/assetcare',
        'ALLOWED_ORIGINS' => 'http://localhost/assetcare',
    ],
    'live' => [
        'DB_HOST'         => 'localhost',                  // Or your hosting MySQL host
        'DB_PORT'         => 3306,
        'DB_NAME'         => 'your_live_database_name',    // e.g. cpaneluser_assetcare_db
        'DB_USER'         => 'your_live_db_username',      // e.g. cpaneluser_dbuser
        'DB_PASS'         => 'your_live_db_password',
        'SMTP_HOST'       => 'smtp.gmail.com',             // Or mail.yourdomain.com
        'SMTP_PORT'       => 587,                          // 587 (STARTTLS) or 465 (SSL)
        'SMTP_USER'       => 'your-email@quantanite.com',
        'SMTP_PASS'       => '',                           // 16-char Gmail App Password or mail password
        'SMTP_FROM_NAME'  => 'AssetCare',
        'APP_URL'         => 'https://yourdomain.com',     // Live URL without trailing slash
        'ALLOWED_ORIGINS' => 'https://yourdomain.com',     // Comma-separated allowed origins
    ],
];
