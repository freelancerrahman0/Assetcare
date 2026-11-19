Part 1: Run the Portal on XAMPP (Local PC)
Step 1: Start XAMPP Services
Open XAMPP Control Panel.
Click Start on Apache and MySQL.
Step 2: Copy Portal Files to htdocs
Download/copy the entire contents of the xampp/ folder into:
C:\xampp\htdocs\assetcare\
Make sure .htaccess is also copied into C:\xampp\htdocs\assetcare\ (enable "Hidden items" in Windows File Explorer if you don't see it).
Step 3: Set Up the Database in phpMyAdmin
Open your browser and go to http://localhost/phpmyadmin.
Create a database named assetcare_db (collation: utf8mb4_unicode_ci) — or if you already have assetcare_db with existing data, keep it.
For a fresh install:
Click assetcare_db → open the Import tab → choose C:\xampp\htdocs\assetcare\database.sql → click Import.
For an upgrade over an existing database (keeps your current data, adds any new tables/columns):
Click assetcare_db → open the Import tab → choose C:\xampp\htdocs\assetcare\schema.sql → click Import.
Step 4: Create & Edit Your One Config File (config.local.php)
Inside C:\xampp\htdocs\assetcare\, copy config.local.example.php and rename the copy to config.local.php (keep your existing config.local.php if you already created it).
Open config.local.php and verify:
Line 9 stays on XAMPP mode:
PHP
define('PORTAL_ENV', 'xampp');
Inside the 'xampp' section, fill in your SMTP details:
'SMTP_USER' => 'your-sender@quantanite.com'
'SMTP_PASS' => 'your-16-char-gmail-app-password'
Leave 'DB_HOST' => '127.0.0.1', 'DB_NAME' => 'assetcare_db', 'DB_USER' => 'root', 'DB_PASS' => '', 'APP_URL' => 'http://localhost/assetcare' (unless your XAMPP MySQL uses a password or different port).
Step 5: Open the Portal
Go to http://localhost/assetcare in your browser.
Sign in and verify Dashboard, Repair Inventory, Slot Details, and Forgot Password email work cleanly.
Part 2: Move from XAMPP to Your Live Server (cPanel / Apache / VPS)
When you are ready to go live from XAMPP, follow these 4 steps:
Step 1: Export Your Database from XAMPP & Import on Live Server
Open http://localhost/phpmyadmin → click assetcare_db → click the Export tab → click Export (downloads assetcare_db.sql with all your real XAMPP assets, slots, and users).
(Or use database.sql if you want a clean initial seed instead of XAMPP data.)
Log into your live hosting panel (e.g., cPanel → MySQL Databases):
Create a new database (e.g., cpaneluser_assetcare_db).
Create a MySQL user with a strong password and assign All Privileges to that database.
Open live phpMyAdmin, click your new live database (cpaneluser_assetcare_db) in the left sidebar, open Import, and import your exported .sql file.
Note for shared hosting: If the .sql file has CREATE DATABASE or USE assetcare_db; at the top and phpMyAdmin gives an access error, open the .sql file in Notepad/VS Code, remove those two lines, save, and re-import into your selected live database.
Step 2: Upload the Portal Files
Upload everything from C:\xampp\htdocs\assetcare\ to your live web directory:
Root domain (e.g. https://assetcare.quantanite.com): upload into /public_html/ (or your subdomain folder).
Subfolder (e.g. https://quantanite.com/assetcare): upload into /public_html/assetcare/.
Must-check: Confirm .htaccess was uploaded (in cPanel File Manager, enable Settings → Show Hidden Files (dotfiles)).
Delete database.sql and schema.sql from the live folder after importing.
Step 3: Switch config.local.php to Live Mode
Open config.local.php on the live server and change only two things:
Switch line 9 from 'xampp' to 'live':
PHP
define('PORTAL_ENV', 'live');
Fill in your 'live' section in the same file:
PHP
'live' => [
    'DB_HOST'         => 'localhost',                 // Or your host's MySQL hostname
    'DB_PORT'         => 3306,
    'DB_NAME'         => 'cpaneluser_assetcare_db',   // Live DB name
    'DB_USER'         => 'cpaneluser_dbuser',         // Live DB username
    'DB_PASS'         => 'YOUR_LIVE_DB_PASSWORD',     // Live DB password
    'SMTP_HOST'       => 'smtp.gmail.com',            // Or mail.yourdomain.com
    'SMTP_PORT'       => 587,                         // 587 (STARTTLS) or 465 (SSL)
    'SMTP_USER'       => 'assetcare@quantanite.com',  // Your sender email
    'SMTP_PASS'       => 'YOUR_16_CHAR_APP_PASSWORD', // App password / mail password
    'SMTP_FROM_NAME'  => 'AssetCare',
    'APP_URL'         => 'https://yourdomain.com',    // Exact live HTTPS URL (no trailing /)
    'ALLOWED_ORIGINS' => 'https://yourdomain.com',    // Exact live HTTPS origin(s)
],
(If the portal is in a subfolder like https://quantanite.com/assetcare, set APP_URL to 'https://quantanite.com/assetcare' and ALLOWED_ORIGINS to 'https://quantanite.com'.)
Step 4: Verify Live Security & Email
Enable SSL (HTTPS) on your domain/subdomain.
Open your live URL (https://...), log in, and test:
Forgot Password (if your hosting blocks port 587, switch 'SMTP_PORT' => 465 or use your host's SMTP like mail.yourdomain.com).
Confirm accessing https://yourdomain.com/config.local.php returns 403 Forbidden (protected by .htaccess).