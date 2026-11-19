<?php
// Built by Abdur Rahman
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function smtpReadResponse($socket): array {
    $response = '';
    $code = 0;
    while (($line = fgets($socket, 2048)) !== false) {
        $response .= $line;
        if (strlen($line) >= 3 && is_numeric(substr($line, 0, 3))) {
            $code = (int)substr($line, 0, 3);
            if (!isset($line[3]) || $line[3] !== '-') {
                break;
            }
        }
    }
    return [$code, $response];
}

function smtpSendCommand($socket, string $command, array $expectedCodes): void {
    fwrite($socket, $command . "\r\n");
    [$code, $resp] = smtpReadResponse($socket);
    if (!in_array($code, $expectedCodes, true)) {
        throw new RuntimeException("SMTP error after command: HTTP/SMTP $code - $resp");
    }
}

function sanitizeHeaderInput(string $val): string {
    return trim(str_replace(["\r", "\n", "\0"], ' ', $val));
}

function getSmtpEhloHost(): string {
    $appHost = defined('APP_URL') ? (string)@parse_url((string)APP_URL, PHP_URL_HOST) : '';
    $serverHost = trim((string)($_SERVER['HTTP_HOST'] ?? ''));
    $serverHost = preg_replace('/:\d+$/', '', $serverHost) ?? '';
    $candidate = $appHost !== '' ? $appHost : $serverHost;
    $clean = preg_replace('/[^a-zA-Z0-9.\-]/', '', $candidate) ?? '';
    return $clean !== '' ? $clean : 'localhost';
}

function sendEmail(string $to, string $subject, string $htmlContent): bool {
    $host = SMTP_HOST;
    $port = SMTP_PORT;
    $user = sanitizeHeaderInput(SMTP_USER);
    $pass = SMTP_PASS;
    $cleanTo = sanitizeHeaderInput($to);
    $cleanSubject = sanitizeHeaderInput($subject);

    if (!$host || !$user || !$pass || !$cleanTo) {
        error_log('[SMTP] Email delivery skipped: SMTP credentials or recipient not configured.');
        return false;
    }

    $caFile = (string)(ini_get('openssl.cafile') ?: ini_get('curl.cainfo') ?: '');
    $hasCaFile = $caFile !== '' && is_file($caFile);
    $verifySsl = defined('SMTP_VERIFY_SSL') ? (bool)SMTP_VERIFY_SSL : $hasCaFile;

    $remote = ($port === 465 ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => $verifySsl,
            'verify_peer_name' => $verifySsl,
            'allow_self_signed' => !$verifySsl
        ]
    ]);

    $errno = 0;
    $errstr = '';
    $socket = @stream_socket_client($remote, $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $context);
    if (!$socket) {
        error_log("[SMTP] Connection failed to $remote: ($errno) $errstr");
        return false;
    }

    try {
        stream_set_timeout($socket, 8);
        [$greetCode, $greetResp] = smtpReadResponse($socket);
        if ($greetCode !== 220) {
            throw new RuntimeException("SMTP unexpected greeting ($greetCode): $greetResp");
        }

        $ehloHost = getSmtpEhloHost();
        smtpSendCommand($socket, 'EHLO ' . $ehloHost, [250]);

        if ($port === 587) {
            smtpSendCommand($socket, 'STARTTLS', [220]);
            $cryptoMethod = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $cryptoMethod |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }
            if (!@stream_socket_enable_crypto($socket, true, $cryptoMethod)) {
                throw new RuntimeException('Failed enabling STARTTLS encryption.');
            }
            smtpSendCommand($socket, 'EHLO ' . $ehloHost, [250]);
        }

        smtpSendCommand($socket, 'AUTH LOGIN', [334]);
        smtpSendCommand($socket, base64_encode($user), [334]);
        smtpSendCommand($socket, base64_encode($pass), [235]);

        smtpSendCommand($socket, "MAIL FROM:<$user>", [250]);
        smtpSendCommand($socket, "RCPT TO:<$cleanTo>", [250, 251]);
        smtpSendCommand($socket, 'DATA', [354]);

        $encodedSubject = '=?UTF-8?B?' . base64_encode($cleanSubject) . '?=';
        $messageId = '<' . bin2hex(random_bytes(12)) . '@quantanite.com>';
        $safeFromName = str_replace('"', '', sanitizeHeaderInput(SMTP_FROM_NAME));
        $headers = [
            'Date: ' . date('r'),
            'From: "' . $safeFromName . '" <' . $user . '>',
            'To: <' . $cleanTo . '>',
            'Subject: ' . $encodedSubject,
            'Message-ID: ' . $messageId,
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'Content-Transfer-Encoding: base64'
        ];

        $body = chunk_split(base64_encode($htmlContent), 76, "\r\n");
        $rawMessage = implode("\r\n", $headers) . "\r\n\r\n" . $body . "\r\n.";

        fwrite($socket, $rawMessage . "\r\n");
        [$dataCode, $dataResp] = smtpReadResponse($socket);
        if ($dataCode !== 250) {
            throw new RuntimeException("SMTP DATA rejected ($dataCode): $dataResp");
        }

        @fwrite($socket, "QUIT\r\n");
        fclose($socket);
        return true;
    } catch (Throwable $e) {
        error_log('[SMTP] Error sending email: ' . $e->getMessage());
        @fclose($socket);
        return false;
    }
}

function sendOtpEmail(string $to, string $username, string $otp): bool {
    $safeUser = htmlspecialchars($username, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeOtp = htmlspecialchars($otp, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $year = date('Y');
    $subject = 'AssetCare - Password Recovery Security Code: ' . sanitizeHeaderInput($otp);

    $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; color: #1e293b; }
    .card { max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); overflow: hidden; border: 1px solid #e2e8f0; }
    .header { background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%); padding: 32px 24px; text-align: center; }
    .header h1 { color: #ffffff; margin: 0; font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
    .header p { color: #bfdbfe; margin: 6px 0 0 0; font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; }
    .content { padding: 36px 32px; }
    .greeting { font-size: 16px; font-weight: 600; color: #0f172a; margin-bottom: 12px; }
    .text { font-size: 14px; line-height: 1.6; color: #475569; margin-bottom: 24px; }
    .otp-container { background: #f8fafc; border: 2px dashed #93c5fd; border-radius: 14px; padding: 24px; text-align: center; margin: 28px 0; }
    .otp-code { font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: 800; color: #1d4ed8; letter-spacing: 10px; margin: 0; }
    .otp-caption { font-size: 12px; color: #64748b; margin-top: 8px; font-weight: 500; }
    .timer-alert { background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 10px; color: #b91c1c; font-size: 13px; font-weight: 600; text-align: center; }
    .footer { background: #f8fafc; padding: 20px 32px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>AssetCare</h1>
      <p>Quantanite IT Infrastructure</p>
    </div>
    <div class="content">
      <div class="greeting">Hello {$safeUser},</div>
      <p class="text">
        A password recovery request was initiated for your AssetCare account. To verify your identity and reset your password, please use the 6-digit one-time security code below:
      </p>
      <div class="otp-container">
        <div class="otp-code">{$safeOtp}</div>
        <div class="otp-caption">One-Time Security Verification Code</div>
      </div>
      <div class="timer-alert">
        &#9888;&#65039; This code is valid for 1 minute only and can only be used once.
      </div>
      <p class="text" style="margin-top: 24px; font-size: 12px; color: #64748b;">
        If you did not request a password reset, please disregard this email or report immediately to Quantanite IT Support (<a href="mailto:itsupport@quantanite.com" style="color:#2563eb;">itsupport@quantanite.com</a>).
      </p>
    </div>
    <div class="footer">
      Quantanite Asset Maintenance Portal &copy; {$year} AssetCare<br>
      Automated Security Notification &bull; Do Not Reply
    </div>
  </div>
</body>
</html>
HTML;

    return sendEmail($to, $subject, $html);
}

function sendWelcomeEmail(string $to, string $username, string $tempPass, string $portalUrl): bool {
    $safeUser = htmlspecialchars($username, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeTo = htmlspecialchars($to, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safePass = htmlspecialchars($tempPass, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeUrl = htmlspecialchars($portalUrl ?: APP_URL, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $year = date('Y');
    $subject = "Welcome to AssetCare - Account Created for $username";

    $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; color: #1e293b; }
    .card { max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); overflow: hidden; border: 1px solid #e2e8f0; }
    .header { background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%); padding: 32px 24px; text-align: center; }
    .header h1 { color: #ffffff; margin: 0; font-size: 24px; font-weight: 700; }
    .header p { color: #bfdbfe; margin: 6px 0 0 0; font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; }
    .content { padding: 36px 32px; }
    .credential-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin: 24px 0; }
    .cred-row { margin-bottom: 10px; font-size: 14px; }
    .cred-row:last-child { margin-bottom: 0; }
    .cred-label { font-weight: 600; color: #64748b; }
    .cred-val { font-weight: 700; color: #0f172a; font-family: monospace; }
    .btn { display: inline-block; width: 100%; box-sizing: border-box; background: #2563eb; color: #ffffff !important; text-align: center; padding: 14px 24px; border-radius: 10px; font-weight: 700; text-decoration: none; margin-top: 12px; }
    .note { font-size: 12px; color: #b45309; background: #fffbeb; border: 1px solid #fef3c7; border-radius: 8px; padding: 12px; margin-top: 20px; }
    .footer { background: #f8fafc; padding: 20px 32px; text-align: center; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>Welcome to AssetCare</h1>
      <p>Quantanite Maintenance Portal</p>
    </div>
    <div class="content">
      <h2 style="font-size: 18px; margin-top: 0; color: #0f172a;">Welcome, {$safeUser}!</h2>
      <p style="font-size: 14px; line-height: 1.6; color: #475569;">
        An administrator has provisioned an account for you on the AssetCare Maintenance Portal.
      </p>
      <div class="credential-box">
        <div class="cred-row"><span class="cred-label">Username:</span> <span class="cred-val">{$safeUser}</span></div>
        <div class="cred-row"><span class="cred-label">Email:</span> <span class="cred-val">{$safeTo}</span></div>
        <div class="cred-row"><span class="cred-label">Temporary Password:</span> <span class="cred-val">{$safePass}</span></div>
      </div>
      <div class="note">
        &#128274; <strong>Mandatory Security Policy:</strong> Upon your first login, the portal will require you to change your temporary password to a private password of your choice.
      </div>
      <a href="{$safeUrl}" class="btn">Login to AssetCare Portal</a>
    </div>
    <div class="footer">
      Quantanite Asset Maintenance Portal &copy; {$year} AssetCare
    </div>
  </div>
</body>
</html>
HTML;

    return sendEmail($to, $subject, $html);
}
