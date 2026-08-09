<?php
/**
 * Bot/Scraper Block - blocks.php
 * No external API calls — all checks run locally with zero overhead.
 *
 * S. Secret token bypass for trusted tools (autoposter etc.)
 * 1. Blocks empty / missing user agents
 * 2. Whitelists legitimate search engine bots (Googlebot, DuckDuckBot etc.)
 * 2b. Rate limits any single IP making too many requests too fast
 * 3. Blocks known bad bots and scrapers by user agent string
 * 4. Blocks outdated Chrome versions used as bot fingerprints
 * 5. Blocks WordPress probe paths (wp-login.php, wp-admin etc.) — site is not WordPress
 * 6. Drag-and-drop puzzle CAPTCHA via verify_overlay.php for all human visitors
 *
 * Logs BLOCKED and CAPTCHA events to alist.txt — one line per entry.
 * Add to .htaccess: php_value auto_prepend_file /home/yourusername/public_html/blocks.php
 */

// ---------------------------------------------------------------
// LOGGING — helpers defined early, rotate_log called AFTER early returns
// ---------------------------------------------------------------
$logFile = '/home/yourusername/public_html/alist.txt';
if (!is_writable(dirname($logFile)) && !@touch($logFile)) {
    $logFile = sys_get_temp_dir() . '/alist.txt';
}

function rotate_log(string $logFile): void {
    if (!file_exists($logFile)) {
        return;
    }
    $size = filesize($logFile);
    if ($size === false || $size < 1048576) {
        return; // Under 1MB — nothing to do
    }

    // Read only a bounded chunk from the end of the file (~1.5MB, enough
    // for well over 5000 typical log lines) instead of loading the
    // entire file into memory with file(). Keeps rotation cheap even
    // if the log has grown large during a traffic burst.
    $handle = @fopen($logFile, 'rb');
    if ($handle === false) {
        return;
    }
    $readSize = (int) min($size, 1572864); // 1.5MB
    fseek($handle, -$readSize, SEEK_END);
    $chunk = fread($handle, $readSize);
    fclose($handle);

    if ($chunk === false) {
        return;
    }

    $lines = explode(PHP_EOL, rtrim($chunk, PHP_EOL));
    // The chunk likely starts mid-line (we seeked from an arbitrary byte
    // offset) — drop that first, possibly-truncated line.
    if ($size > $readSize && count($lines) > 1) {
        array_shift($lines);
    }

    if (count($lines) > 5000) {
        $lines = array_slice($lines, -5000); // Keep last 5000 lines
    }

    file_put_contents($logFile, implode(PHP_EOL, $lines) . PHP_EOL, LOCK_EX);
}

function writelog(string $logFile, string $status, string $reason, string $ip): void {
    $date    = date('Y-m-d H:i:s');
    $method  = $_SERVER['REQUEST_METHOD']  ?? '-';
    $scheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host    = $_SERVER['HTTP_HOST']       ?? '-';
    $uri     = $_SERVER['REQUEST_URI']     ?? '-';
    $fullUrl = $scheme . '://' . $host . $uri;
    $ua      = $_SERVER['HTTP_USER_AGENT'] ?? 'NONE';
    $referer = $_SERVER['HTTP_REFERER']    ?? '-';
    $port    = $_SERVER['REMOTE_PORT']     ?? '-';

    $line = "[{$date}] {$status} | {$reason} | IP:{$ip} | {$method} {$fullUrl} | REF:{$referer} | PORT:{$port} | UA:{$ua}" . PHP_EOL;
    file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

// ---------------------------------------------------------------
// HELPER — Cloudflare-aware real IP resolution
// Works whether or not the site is actually behind Cloudflare:
//   - If the direct connection (REMOTE_ADDR) comes from a known
//     Cloudflare IP range, trust CF-Connecting-IP for the real visitor IP.
//   - Otherwise, REMOTE_ADDR is used as-is and CF headers are ignored,
//     so they can't be spoofed by a random visitor to fake an IP.
// Cloudflare IP ranges: https://www.cloudflare.com/ips/
// ---------------------------------------------------------------
const CLOUDFLARE_IPV4_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

const CLOUDFLARE_IPV6_RANGES = [
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function ipv4InRange(string $ip, string $cidr): bool {
    [$subnet, $bits] = explode('/', $cidr);
    $ipLong     = ip2long($ip);
    $subnetLong = ip2long($subnet);
    if ($ipLong === false || $subnetLong === false) {
        return false;
    }
    $mask = -1 << (32 - (int) $bits);
    return ($ipLong & $mask) === ($subnetLong & $mask);
}

function ipv6InRange(string $ip, string $cidr): bool {
    [$subnet, $bits] = explode('/', $cidr);
    $ipBin     = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false) {
        return false;
    }
    $bits      = (int) $bits;
    $bytes     = intdiv($bits, 8);
    $remainder = $bits % 8;

    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
        return false;
    }
    if ($remainder === 0) {
        return true;
    }
    $mask = ~(0xFF >> $remainder) & 0xFF;
    return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
}

function isCloudflareIp(string $ip): bool {
    if (strpos($ip, ':') !== false) {
        foreach (CLOUDFLARE_IPV6_RANGES as $range) {
            if (ipv6InRange($ip, $range)) {
                return true;
            }
        }
        return false;
    }
    foreach (CLOUDFLARE_IPV4_RANGES as $range) {
        if (ipv4InRange($ip, $range)) {
            return true;
        }
    }
    return false;
}

function getRealIp(): string {
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Only trust CF-Connecting-IP if the direct connection is actually
    // from Cloudflare. If the site isn't behind Cloudflare, this never
    // matches, so REMOTE_ADDR is always used — nothing changes for you.
    if (isCloudflareIp($remoteAddr) && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $cfIp = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
        if (filter_var($cfIp, FILTER_VALIDATE_IP)) {
            return $cfIp;
        }
    }

    return $remoteAddr;
}

// ---------------------------------------------------------------
// RATE LIMITING — hard cap on requests/second from a single IP
// Uses APCu (in-memory, near-zero overhead) when available, since
// that's the common case on cPanel/CloudLinux hosting. Falls back
// to a single small locked file if APCu isn't enabled, so this
// still works everywhere — just with a little more I/O per request.
//
// Tune these three constants to taste:
//   RATE_LIMIT_MAX_REQUESTS — how many requests are allowed...
//   RATE_LIMIT_WINDOW_SECONDS — ...within this many seconds...
//   RATE_LIMIT_LOCKOUT_SECONDS — ...before the IP is hard-blocked
//                                  for this long.
// ---------------------------------------------------------------
const RATE_LIMIT_MAX_REQUESTS    = 25;   // requests
const RATE_LIMIT_WINDOW_SECONDS  = 10;   // per this many seconds
const RATE_LIMIT_LOCKOUT_SECONDS = 300;  // then blocked for this long

// Fallback-file store lives next to the log file. Bounded in size
// (see prune step below) so it can never grow without limit.
function rateLimitFilePath(string $logFile): string {
    return dirname($logFile) . '/ratelimit.dat';
}

function apcuAvailable(): bool {
    static $available = null;
    if ($available === null) {
        $available = function_exists('apcu_fetch')
            && function_exists('apcu_store')
            && function_exists('apcu_inc')
            && @apcu_store('sb_rl_selftest', 1, 5) === true;
    }
    return $available;
}

// Returns 0 if the request is allowed, or the number of seconds
// remaining in the lockout if this IP should be blocked right now.
function rateLimitExceeded(string $ip, string $logFile): int {
    return apcuAvailable()
        ? rateLimitCheckApcu($ip)
        : rateLimitCheckFile($ip, $logFile);
}

function rateLimitCheckApcu(string $ip): int {
    $now      = time();
    $lockKey  = 'sb_rl_lock_' . $ip;
    $countKey = 'sb_rl_count_' . $ip;

    // Already in a lockout from a previous flood? Cheapest possible
    // exit — one APCu read, nothing else.
    $lockedUntil = apcu_fetch($lockKey);
    if ($lockedUntil !== false && $lockedUntil > $now) {
        return $lockedUntil - $now;
    }

    // apcu_inc() atomically creates-and-increments in one call —
    // no separate exists-check needed, and it's concurrency-safe
    // across PHP-FPM/Apache workers sharing the same memory segment.
    $count = apcu_inc($countKey, 1, $success, RATE_LIMIT_WINDOW_SECONDS);
    if (!$success) {
        apcu_store($countKey, 1, RATE_LIMIT_WINDOW_SECONDS);
        $count = 1;
    }

    if ($count > RATE_LIMIT_MAX_REQUESTS) {
        apcu_store($lockKey, $now + RATE_LIMIT_LOCKOUT_SECONDS, RATE_LIMIT_LOCKOUT_SECONDS);
        return RATE_LIMIT_LOCKOUT_SECONDS;
    }

    return 0;
}

// File-based fallback. Single small file, one flock'd read-modify-
// write per request. Entries prune themselves on every write so the
// file can't grow unbounded even under sustained traffic.
function rateLimitCheckFile(string $ip, string $logFile): int {
    $path = rateLimitFilePath($logFile);
    $now  = time();

    $handle = @fopen($path, 'c+');
    if ($handle === false) {
        return 0; // Can't open the store — fail open, don't block real visitors
    }

    if (!flock($handle, LOCK_EX)) {
        fclose($handle);
        return 0; // Fail open rather than risk hanging on lock contention
    }

    $size = filesize($path);
    $raw  = $size > 0 ? fread($handle, $size) : '';
    $data = $raw !== '' ? @unserialize($raw) : [];
    if (!is_array($data)) {
        $data = [];
    }

    // Prune anything whose window AND lockout have both expired, so
    // the file only ever holds currently-relevant IPs. Cap the total
    // count as a hard safety net against unbounded growth.
    foreach ($data as $entryIp => $entry) {
        $windowExpired  = ($entry['windowStart'] ?? 0) + RATE_LIMIT_WINDOW_SECONDS < $now;
        $lockoutExpired = ($entry['lockedUntil'] ?? 0) < $now;
        if ($windowExpired && $lockoutExpired) {
            unset($data[$entryIp]);
        }
    }
    if (count($data) > 5000) {
        // Extremely unlikely on a site this size, but bail safely —
        // drop the oldest half rather than let the file balloon.
        uasort($data, fn($a, $b) => ($a['windowStart'] ?? 0) <=> ($b['windowStart'] ?? 0));
        $data = array_slice($data, (int) (count($data) / 2), null, true);
    }

    $entry = $data[$ip] ?? ['count' => 0, 'windowStart' => $now, 'lockedUntil' => 0];

    $result = 0;
    if ($entry['lockedUntil'] > $now) {
        $result = $entry['lockedUntil'] - $now;
    } else {
        if ($entry['windowStart'] + RATE_LIMIT_WINDOW_SECONDS < $now) {
            // Window expired — start a fresh one
            $entry['count']       = 1;
            $entry['windowStart'] = $now;
        } else {
            $entry['count']++;
        }

        if ($entry['count'] > RATE_LIMIT_MAX_REQUESTS) {
            $entry['lockedUntil'] = $now + RATE_LIMIT_LOCKOUT_SECONDS;
            $result = RATE_LIMIT_LOCKOUT_SECONDS;
        }
    }

    $data[$ip] = $entry;

    ftruncate($handle, 0);
    rewind($handle);
    fwrite($handle, serialize($data));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);

    return $result;
}

// ---------------------------------------------------------------
// HELPER — check if visitor already passed CAPTCHA
// Uses the resolved real IP consistently (Cloudflare-aware, see getRealIp())
// ---------------------------------------------------------------
function already_verified(string $ip): bool {
    if (!empty($_SESSION['verified_human']) && ($_SESSION['verified_ip'] ?? '') === $ip) {
        return true;
    }
    if (!empty($_COOKIE['human_ticket']) && $_COOKIE['human_ticket'] === 'verified') {
        return true;
    }
    if (!empty($_COOKIE['human_ticket_mobile']) && $_COOKIE['human_ticket_mobile'] === 'verified') {
        return true;
    }
    return false;
}

// ---------------------------------------------------------------
// HELPER — serve the CAPTCHA challenge and stop execution
// ---------------------------------------------------------------
function serve_captcha(string $logFile, string $reason, string $ip): void {
    writelog($logFile, 'CAPTCHA', $reason, $ip);
    require __DIR__ . '/verify_overlay.php';
    exit;
}

// ---------------------------------------------------------------
// SECRET TOKEN BYPASS — for trusted automated tools e.g. autoposter
// Load from environment variable to avoid hardcoding secrets in source.
// Set on your server: SetEnv AUTOPOSTER_TOKEN your_secret_here  (in .htaccess or httpd.conf)
// Autoposter sends header: X-Autoposter-Token: <token> to bypass all checks silently
// ---------------------------------------------------------------
$secretToken = getenv('AUTOPOSTER_TOKEN') ?: '';
if ($secretToken !== '' && ($_SERVER['HTTP_X_AUTOPOSTER_TOKEN'] ?? '') === $secretToken) {
    return; // Trusted request — skip everything silently
}

// ---------------------------------------------------------------
// GET VISITOR IP — Cloudflare-aware (falls back to REMOTE_ADDR if
// the request isn't actually coming through Cloudflare)
// ---------------------------------------------------------------
$userAgent   = $_SERVER['HTTP_USER_AGENT'] ?? '';
$visitorIp   = getRealIp();
$requestPath = strtok($_SERVER['REQUEST_URI'] ?? '', '?');

// ---------------------------------------------------------------
// 1. BLOCK MISSING / EMPTY USER-AGENTS
//    Hard 403 — bots with no UA can't solve a CAPTCHA anyway
// ---------------------------------------------------------------
if (trim($userAgent) === '') {
    rotate_log($logFile);
    writelog($logFile, 'BLOCKED', 'EMPTY_UA', $visitorIp);
    http_response_code(403);
    echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied.</p></body></html>';
    exit;
}

// ---------------------------------------------------------------
// 2. WHITELIST LEGITIMATE SEARCH ENGINE BOTS
//    Let through silently — no logging needed for good bots
// ---------------------------------------------------------------
$allowedBots = [
    'googlebot', 'google-inspectiontool', 'adsbot-google', 'mediapartners-google',
    'googleother', 'bingbot', 'slurp', 'duckduckbot', 'facebot', 'facebookexternalhit',
    'twitterbot', 'linkedinbot', 'applebot', 'gtmetrix',
];

$uaLower = strtolower($userAgent);

foreach ($allowedBots as $good) {
    if (strpos($uaLower, $good) !== false) {
        return; // Good bot — exit early, no log rotation needed
    }
}

// ---------------------------------------------------------------
// 2b. RATE LIMIT — hard cap on requests/second from a single IP.
//    Placed here (after the good-bot whitelist, before the heavier
//    checks) so a flooding client is rejected as cheaply as possible:
//    no old-Chrome regex, no WP-probe loop, and critically, no
//    CAPTCHA session/puzzle generation.
// ---------------------------------------------------------------
$retryAfter = rateLimitExceeded($visitorIp, $logFile);
if ($retryAfter > 0) {
    rotate_log($logFile);
    writelog($logFile, 'BLOCKED', 'RATE_LIMIT', $visitorIp);
    http_response_code(429);
    header('Retry-After: ' . $retryAfter);
    echo '<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head><body><h1>429 Too Many Requests</h1><p>Please slow down and try again shortly.</p></body></html>';
    exit;
}

// ---------------------------------------------------------------
// 3. BLOCK KNOWN SCRAPERS / BOTS BY USER-AGENT
//    Hard 403 — these are definitively non-human tools
// ---------------------------------------------------------------
$blockedAgents = [
    'curl', 'wget', 'libwww', 'python', 'java/', 'ruby/', 'perl/',
    'go-http', 'httpclient', 'okhttp', 'axios', 'node-fetch',
    'scrapy', 'mechanize', 'phantomjs', 'headlesschrome', 'selenium',
    'puppeteer', 'playwright', 'htmlunit', 'nutch',
    'ahrefsbot', 'semrushbot', 'dotbot', 'mj12bot', 'blexbot',
    'yandexbot', 'baiduspider', 'sogou', 'exabot', 'sistrix',
    'rogerbot', 'bytespider', 'petalbot', 'zgrab', 'masscan',
    'nmap', 'nikto', 'sqlmap', 'dirbuster', 'nuclei',
    'bot', 'crawler', 'spider', 'scraper', 'fetcher', 'harvest',
    'scan', 'exploit', 'inject', 'attack',
    // Passkey probing and authentication reconnaissance
    'passkey-domain-check',
    // CMS/WordPress fingerprinting tool
    'cms-detector',
];

foreach ($blockedAgents as $agent) {
    if (strpos($uaLower, $agent) !== false) {
        rotate_log($logFile);
        writelog($logFile, 'BLOCKED', 'BAD_UA:' . $agent, $visitorIp);
        http_response_code(403);
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied.</p></body></html>';
        exit;
    }
}

// ---------------------------------------------------------------
// 4. BLOCK OUTDATED CHROME VERSIONS — bot fingerprint
//    No real user runs Chrome below 110 in 2026.
//    Scrapers fake old Chrome UAs to avoid detection.
// ---------------------------------------------------------------
if (preg_match('/Chrome\/(\d+)\./', $userAgent, $matches)) {
    $chromeMajor = (int) $matches[1];
    if ($chromeMajor < 110) {
        rotate_log($logFile);
        writelog($logFile, 'BLOCKED', 'OLD_CHROME:' . $chromeMajor, $visitorIp);
        http_response_code(403);
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied.</p></body></html>';
        exit;
    }
}

// ---------------------------------------------------------------
// 5. BLOCK WORDPRESS PROBE PATHS — site is not WordPress
//    Returns your custom 404 page. Using 404 (not 403) tells scanners
//    the path simply doesn't exist, which discourages repeat probing.
// ---------------------------------------------------------------
$wpProbePaths = [
    '/wp-login.php', '/wp-admin', '/wp-admin/', '/xmlrpc.php',
    '/wp-config.php', '/wp-includes', '/wp-content',
    '/.well-known/passkey-endpoints', '/.well-known/passkey-domain-check',
];

foreach ($wpProbePaths as $probe) {
    if ($requestPath === $probe || strpos($requestPath, $probe . '/') === 0) {
        rotate_log($logFile);
        writelog($logFile, 'BLOCKED', 'WP_PROBE:' . $requestPath, $visitorIp);
        http_response_code(404);
        $custom404 = '/home/yourusername/public_html/404.shtml';
        if (file_exists($custom404)) {
            readfile($custom404);
        } else {
            echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>';
        }
        exit;
    }
}

// ---------------------------------------------------------------
// 5b. BLOCK KNOWN NON-EXISTENT ICON/FAVICON PATHS
//     Real browsers silently ignore a missing icon — there is never
//     a legitimate reason to challenge a visitor with the CAPTCHA
//     puzzle over one of these requests. Catching them here (before
//     section 6) skips session creation and puzzle generation
//     entirely, which matters during high-volume bursts that target
//     these exact files (seen repeatedly: 07/06, 07/16, 08/06).
//     None of these files exist on this server. Returns a plain 404.
// ---------------------------------------------------------------
$iconPaths = [
    '/favicon.ico',
    '/apple-touch-icon.png',
    '/apple-touch-icon-precomposed.png',
    '/apple-touch-icon-120x120.png',
    '/apple-touch-icon-120x120-precomposed.png',
];

if (in_array($requestPath, $iconPaths, true)) {
    rotate_log($logFile);
    writelog($logFile, 'BLOCKED', 'ICON_PROBE:' . $requestPath, $visitorIp);
    http_response_code(404);
    $custom404 = '/home/yourusername/public_html/404.shtml';
    if (file_exists($custom404)) {
        readfile($custom404);
    } else {
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>';
    }
    exit;
}

// ---------------------------------------------------------------
// 6. DRAG-AND-DROP PUZZLE CAPTCHA — challenge ALL visitors on first visit
//    Once solved, the session + cookie lets them through freely.
//    Skip AJAX endpoints so background requests don't get interrupted.
//
//    SESSION — started here rather than at the top of the file, so
//    bots blocked in sections 1-5 never create an unnecessary PHP
//    session file. Safe: no output has been sent yet at this point
//    for any request that reaches this line.
// ---------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$skipCaptcha = ['/includes/ajax/data/live.php', '/includes/ajax/chat/live.php'];

if (!already_verified($visitorIp) && !in_array($requestPath, $skipCaptcha, true)) {
    rotate_log($logFile);
    serve_captcha($logFile, 'CAPTCHA_ALL', $visitorIp);
}
