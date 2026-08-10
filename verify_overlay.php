<?php
// verify_overlay.php - Drag & Drop Puzzle CAPTCHA v3
// 5-piece board, 3 gaps, 3 jigsaw pieces must each be placed in correct slot.
// Classic jigsaw tab/blank shapes clipped via canvas path.

if (session_status() === PHP_SESSION_NONE) { session_start(); }

$error = '';

// Reuses getRealIp() from blocks.php (already defined — this file is require()'d
// from inside blocks.php, so the function exists in scope). Falls back to
// REMOTE_ADDR only if this file is ever somehow loaded standalone.
function overlay_get_ip(): string {
    return function_exists('getRealIp') ? getRealIp() : ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}
$visitor_ip = overlay_get_ip();

// ── Rate limiting ────────────────────────────────────────────────
$now          = time();
$fail_count   = (int)($_SESSION['captcha_fails']        ?? 0);
$locked_until = (int)($_SESSION['captcha_locked_until'] ?? 0);

if ($locked_until > $now) {
    $wait  = $locked_until - $now;
    $error = "Too many incorrect attempts. Please wait {$wait} second" . ($wait===1?'':'s') . " and try again.";
    unset($_SESSION['puzzle_slots'], $_SESSION['puzzle_theme']);
}

// ── Generate puzzle state ────────────────────────────────────────
// 5 columns, 3 are gaps (missing pieces), stored as sorted array of slot indices.
// puzzle_order = shuffled display order for tray pieces so piece 1 isn't always leftmost.
if (!isset($_SESSION['puzzle_slots'])) {
    $slots = range(0, 4);
    shuffle($slots);
    $missing = array_slice($slots, 0, 3); // 3 missing slot indices
    sort($missing);
    $order = [0, 1, 2];
    shuffle($order);
    $_SESSION['puzzle_slots'] = $missing;  // e.g. [0,2,4] — correct slot per piece index
    $_SESSION['puzzle_order'] = $order;    // e.g. [2,0,1] — display order in tray
    $_SESSION['puzzle_theme'] = rand(0, 5);
    $_SESSION['puzzle_started_at'] = time();
}

if (isset($_SESSION['puzzle_slots']) && !isset($_SESSION['puzzle_started_at'])) {
    $_SESSION['puzzle_started_at'] = time();
}

// ── CSRF ─────────────────────────────────────────────────────────
if (empty($_SESSION['captcha_csrf'])) {
    $_SESSION['captcha_csrf'] = bin2hex(random_bytes(16));
}

// ── Handle POST ──────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['answers']) && empty($error)) {
    $csrf_ok = hash_equals($_SESSION['captcha_csrf'], $_POST['captcha_csrf'] ?? '');
    if (!$csrf_ok) {
        $error = "Security token mismatch — please refresh and try again.";
    } else {
        $minSeconds = defined('CAPTCHA_MIN_SECONDS') ? CAPTCHA_MIN_SECONDS : 3;
        $startedAt  = (int)($_SESSION['puzzle_started_at'] ?? 0);
        $interacted = ($_POST['puzzle_interacted'] ?? '') === '1';
        $elapsed    = $now - $startedAt;
        $gateOk     = $interacted && $startedAt > 0 && $elapsed >= $minSeconds;

        if (!$gateOk) {
            $error = "Please drag each piece into place to continue.";
            $correct = false;
        } else {
        // answers is JSON array of {piece_index, slot_index} pairs
        $submitted = json_decode($_POST['answers'], true);
        $expected  = $_SESSION['puzzle_slots']; // [slot0, slot1, slot2] sorted

        $correct = false;
        if (is_array($submitted) && count($submitted) === 3) {
            // submitted is an ordered array — element 0 was placed first, 1 second, 2 third.
            // For correct answer:
            //   - submitted[i]['slot'] must equal expected[submitted[i]['piece']]  (right slot)
            //   - submitted[i]['tray_label'] must equal i+1                        (right order)
            $correct = true;
            for ($i = 0; $i < 3; $i++) {
                $s          = $submitted[$i];
                $pieceIdx   = (int)($s['piece']       ?? -1);
                $slotIdx    = (int)($s['slot']        ?? -1);
                $trayLabel  = (int)($s['tray_label']  ?? -1);
                // Must be placed in order: first piece placed must have tray_label 1, second 2, third 3
                if ($trayLabel !== $i + 1)              { $correct = false; break; }
                // Must go into the correct board slot
                if ($slotIdx !== ($expected[$pieceIdx] ?? -99)) { $correct = false; break; }
            }
        }
        }

        if ($correct) {
            unset($_SESSION['puzzle_slots'], $_SESSION['puzzle_theme'],
                  $_SESSION['puzzle_started_at'],
                  $_SESSION['captcha_csrf'], $_SESSION['captcha_fails'],
                  $_SESSION['captcha_fail_time'], $_SESSION['captcha_locked_until'],
                  $_SESSION['already_logged']);
            $_SESSION['verified_human'] = true;
            $_SESSION['verified_ip']    = $visitor_ip;

            $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                        || ($_SERVER['SERVER_PORT'] ?? '') === '443';
            $ticketTtl = defined('TICKET_TTL_SECONDS') ? TICKET_TTL_SECONDS : 86400;
            $cookieOpts = [
                'expires'  => time() + $ticketTtl,
                'path'     => '/',
                'httponly' => true,
                'secure'   => $is_https,
                'samesite' => 'Lax',
            ];
            setcookie('human_ticket', issueHumanTicket($visitor_ip), $cookieOpts);
            // Retire legacy static cookies from earlier versions
            setcookie('human_ticket_mobile', '', ['expires' => 1, 'path' => '/']);
            $redirect = htmlspecialchars(
                safeRedirectPath($_SESSION['blocked_uri'] ?? '/'),
                ENT_QUOTES,
                'UTF-8'
            );
            unset($_SESSION['blocked_uri']);

            // Meta refresh instead of Refresh header — mobile browsers (especially
            // iOS Safari) sometimes follow the Refresh header before fully committing
            // the cookie. A meta refresh tag forces the browser to parse the full
            // response (and write the cookie) before navigating. Zero visible delay.
            ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url=<?= $redirect ?>">
<title>Verified</title>
</head>
<body></body>
</html>
<?php
            exit;
        } else {
            $fail_count++;
            $_SESSION['captcha_fails']     = $fail_count;
            $_SESSION['captcha_fail_time'] = $now;
            if ($fail_count >= 5) {
                $_SESSION['captcha_locked_until'] = $now + 60;
                $_SESSION['captcha_fails']        = 0;
                $error = "Too many incorrect attempts. Please wait 60 seconds and try again.";
            } elseif ($gateOk) {
                $remaining = 5 - $fail_count;
                $error = "Incorrect placement — try again. ({$remaining} attempt" . ($remaining===1?'':'s') . " remaining)";
            }
            // Reset puzzle
            $slots = range(0, 4); shuffle($slots);
            $missing = array_slice($slots, 0, 3); sort($missing);
            $order = [0, 1, 2]; shuffle($order);
            $_SESSION['puzzle_slots'] = $missing;
            $_SESSION['puzzle_order'] = $order;
            $_SESSION['puzzle_theme'] = rand(0, 5);
            $_SESSION['puzzle_started_at'] = time();
            $_SESSION['captcha_csrf'] = bin2hex(random_bytes(16));
        }
    }
}

if (empty($_SESSION['blocked_uri'])) {
    $_SESSION['blocked_uri'] = $_SERVER['REQUEST_URI'] ?? '/';
}

$missingSlots = $_SESSION['puzzle_slots']; // e.g. [0,2,4] — correct slot per piece index
$trayOrder    = $_SESSION['puzzle_order']; // e.g. [2,0,1] — shuffled display order in tray
$puzzleTheme  = (int)$_SESSION['puzzle_theme'];
$csrfToken    = $_SESSION['captcha_csrf'];
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Check</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

@keyframes borderGlow{0%,100%{opacity:.6}50%{opacity:1}}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulseRing{0%{transform:scale(1);opacity:.6}100%{transform:scale(1.4);opacity:0}}
@keyframes popIn{0%{transform:scale(.8);opacity:0}100%{transform:scale(1);opacity:1}}

body{
    font-family:'Inter',sans-serif;background:#080810;
    display:flex;align-items:center;justify-content:center;
    min-height:100vh;padding:20px;
    background-image:
        radial-gradient(ellipse at 15% 50%,rgba(80,40,220,.18) 0%,transparent 55%),
        radial-gradient(ellipse at 85% 20%,rgba(220,40,100,.12) 0%,transparent 50%),
        radial-gradient(ellipse at 50% 90%,rgba(20,180,180,.08) 0%,transparent 50%);
}
.card{
    background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.09);
    border-radius:24px;padding:36px 30px 28px;max-width:580px;width:100%;
    text-align:center;backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);
    box-shadow:0 0 0 1px rgba(255,255,255,.04),0 32px 80px rgba(0,0,0,.65);
    animation:fadeIn .35s ease both;position:relative;
}
.card::before{
    content:'';position:absolute;top:0;left:10%;right:10%;height:1px;
    background:linear-gradient(90deg,transparent,rgba(99,51,255,.8),rgba(233,69,96,.8),transparent);
    animation:borderGlow 3s ease-in-out infinite;
}
.shield-wrap{position:relative;width:52px;height:52px;margin:0 auto 18px}
.shield-wrap .ring{position:absolute;inset:-4px;border-radius:17px;border:1.5px solid rgba(99,51,255,.5);animation:pulseRing 2.5s ease-out infinite}
.shield-icon{width:52px;height:52px;background:linear-gradient(135deg,#5020d0,#c0305a);border-radius:15px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 8px 24px rgba(80,32,200,.4)}
h1{font-size:1.2rem;font-weight:600;color:#f0f0ff;margin-bottom:5px;letter-spacing:-.4px}
p.subtitle{font-size:.82rem;color:rgba(255,255,255,.36);margin-bottom:22px;line-height:1.55}

.puzzle-wrapper{background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.07);border-radius:16px;padding:16px 16px 12px;margin-bottom:18px}
.puzzle-instruction{font-size:.7rem;color:rgba(255,255,255,.3);text-transform:uppercase;letter-spacing:1.4px;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.puzzle-instruction::before,.puzzle-instruction::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.07)}

/* Board — 5 columns */
.puzzle-board{display:flex;gap:2px;margin-bottom:16px;height:130px;position:relative}
.board-slot{flex:1;position:relative;border-radius:2px;overflow:visible}
.board-slot canvas{display:block;position:absolute;top:0;left:0;width:100%;height:100%}

/* Drop zones overlay — shown when dragging */
.drop-target{
    position:absolute;inset:0;border-radius:3px;
    border:2px dashed rgba(99,51,255,0);
    background:rgba(99,51,255,0);
    transition:border-color .15s,background .15s,transform .12s;
    z-index:10;pointer-events:none;
}
.drop-target.active{pointer-events:all;cursor:pointer}
.drop-target.drag-over{border-color:#7c4dff;background:rgba(99,51,255,.25);transform:scale(1.04)}
.drop-target.filled{border-color:rgba(46,204,113,.6);background:rgba(46,204,113,.1)}
.drop-target.wrong{border-color:rgba(220,50,80,.7);background:rgba(220,50,80,.15)}

/* Progress indicator */
.progress-row{display:flex;align-items:center;justify-content:center;gap:6px;margin-bottom:14px}
.prog-dot{width:8px;height:8px;border-radius:50%;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.15);transition:background .3s,border-color .3s}
.prog-dot.done{background:#2ecc71;border-color:#2ecc71;box-shadow:0 0 6px rgba(46,204,113,.5)}
.prog-label{font-size:.7rem;color:rgba(255,255,255,.2);letter-spacing:.5px}

/* Piece tray */
.piece-tray{display:flex;gap:10px;justify-content:center;align-items:flex-end;min-height:90px}
.piece-wrap{
    display:flex;flex-direction:column;align-items:center;gap:6px;
    cursor:grab;transition:transform .15s,opacity .3s;
    user-select:none;-webkit-user-select:none;
}
.piece-wrap.used{opacity:.25;pointer-events:none}
.piece-wrap:hover:not(.used){transform:translateY(-4px)}
.piece-wrap:active:not(.used){cursor:grabbing}
.piece-canvas-wrap{
    border-radius:4px;overflow:hidden;
    box-shadow:0 4px 18px rgba(99,51,255,.4),0 0 0 1.5px rgba(99,51,255,.5);
    transition:box-shadow .15s;
    width:70px;height:90px;position:relative;flex-shrink:0;
}
.piece-wrap:hover:not(.used) .piece-canvas-wrap{box-shadow:0 8px 28px rgba(99,51,255,.6),0 0 0 2px rgba(99,51,255,.7)}
.piece-canvas-wrap canvas{display:block;width:100%;height:100%}
.piece-label{font-size:.62rem;color:rgba(255,255,255,.22);letter-spacing:.6px;text-transform:uppercase}

/* Ghost */
.dragging-ghost{position:fixed;pointer-events:none;z-index:9999;opacity:.9;transform:translate(-50%,-50%) scale(1.08);border-radius:4px;overflow:hidden;box-shadow:0 16px 40px rgba(0,0,0,.7);display:none;width:70px;height:90px}
.dragging-ghost canvas{display:block;width:100%;height:100%}

.error-msg{background:rgba(220,50,80,.1);border:1px solid rgba(220,50,80,.28);color:#f47;border-radius:10px;padding:10px 14px;font-size:.82rem;margin-bottom:16px;display:flex;align-items:center;gap:8px;text-align:left}
.footer-note{margin-top:16px;font-size:.67rem;color:rgba(255,255,255,.14);display:flex;align-items:center;justify-content:center;gap:5px}
.footer-note::before{content:'🔒';font-size:10px}
#verify-form{display:none}
.success-flash{display:none;position:fixed;inset:0;background:rgba(30,180,100,.12);z-index:100;align-items:center;justify-content:center;flex-direction:column;gap:12px;backdrop-filter:blur(4px)}
.success-flash .check{font-size:3.5rem;animation:popIn .25s ease both}
.success-flash .msg{font-size:.9rem;color:rgba(255,255,255,.6);animation:fadeIn .3s ease .15s both}

@media(max-width:500px){
    .card{padding:22px 14px 20px}
    .puzzle-board{height:80px}
    .piece-canvas-wrap{width:56px;height:80px}
    .dragging-ghost{width:56px;height:80px}
    .piece-tray{gap:6px}
}
</style>
</head>
<body>

<div class="success-flash" id="successFlash">
    <div class="check">✓</div>
    <div class="msg">Verified — loading your page…</div>
</div>

<div class="card">
    <div class="shield-wrap"><div class="ring"></div><div class="shield-icon">🛡️</div></div>
    <h1>Security Verification</h1>
    <p class="subtitle">Drag all 3 pieces into their correct slots to continue — use the shape of each piece to find where it fits.</p>

    <?php if (!empty($error)): ?>
        <div class="error-msg">⚠️ <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <div class="puzzle-wrapper">
        <div class="puzzle-instruction">Complete the puzzle</div>

        <div class="progress-row">
            <span class="prog-label">Placed:</span>
            <div class="prog-dot" id="dot0"></div>
            <div class="prog-dot" id="dot1"></div>
            <div class="prog-dot" id="dot2"></div>
        </div>

        <div class="puzzle-board" id="puzzleBoard"></div>

        <div class="piece-tray" id="pieceTray"></div>
    </div>

    <form method="POST" action="" id="verify-form">
        <input type="hidden" name="answers" id="answersInput" value="">
        <input type="hidden" name="puzzle_interacted" id="puzzleInteracted" value="0">
        <input type="hidden" name="captcha_csrf" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
    </form>

    <p class="footer-note">Automated access is not permitted</p>
</div>

<div class="dragging-ghost" id="draggingGhost"><canvas id="ghostCanvas"></canvas></div>

<script>
(function(){
    // ── Config from PHP ───────────────────────────────────────────
    const MISSING_SLOTS = <?= json_encode($missingSlots) ?>; // e.g. [0,2,4] — correct slot per piece index
    const TRAY_ORDER    = <?= json_encode($trayOrder) ?>;    // e.g. [2,0,1] — shuffled display order in tray
    const THEME_INDEX   = <?= $puzzleTheme ?>;
    const BOARD_COLS    = 5;

    // ── Themes ───────────────────────────────────────────────────
    const THEMES = [
        {sky0:'#050510',sky1:'#1a0a3a',ground:'#0d0d1a',horizon:'#2a1060',accent:'#c060ff',star:true, style:'city'},
        {sky0:'#020818',sky1:'#041830',ground:'#021020',horizon:'#0a3060',accent:'#00e5ff',star:true, style:'ocean'},
        {sky0:'#1a0500',sky1:'#6b1800',ground:'#2d0a00',horizon:'#ff4500',accent:'#ff8c00',star:false,style:'volcano'},
        {sky0:'#010a10',sky1:'#003020',ground:'#020f08',horizon:'#00c060',accent:'#80ffcc',star:true, style:'aurora'},
        {sky0:'#060318',sky1:'#180630',ground:'#0a0318',horizon:'#8800cc',accent:'#ff00aa',star:false,style:'cyber'},
        {sky0:'#1a0820',sky1:'#6b2000',ground:'#3d1500',horizon:'#ff6030',accent:'#ffd060',star:true, style:'desert'},
    ];
    const T = THEMES[THEME_INDEX];

    // ── Seeded random ─────────────────────────────────────────────
    function seededRand(seed){let s=seed;return()=>{s=(s*1664525+1013904223)&0xffffffff;return(s>>>0)/0xffffffff;};}

    // ── Jigsaw path helper ────────────────────────────────────────
    // Draws a jigsaw clip path for one board slot.
    // tab = 1 means tab sticks OUT, -1 means blank cuts IN, 0 means flat (edge)
    // sides: {top, right, bottom, left}  each -1|0|1
    // The tab direction is deterministic based on slot position so neighbours interlock.
    function slotShape(col) {
        // Left/right boundaries interlock between neighbours
        const lrBounds = [1, -1, 1, -1]; // right-side tab for cols 0-3

        // Top/bottom tabs — unique per column, alternate so each piece has a distinct silhouette.
        // These are board-edge pieces so top/bottom don't need to interlock with another row,
        // but they vary per column so every piece shape is different.
        const topTabs    = [1, -1,  1, -1,  1]; // per col: 1=tab out, -1=blank in
        const bottomTabs = [-1,  1, -1,  1, -1]; // opposite of top so shape is asymmetric

        return {
            top:    topTabs[col],
            bottom: bottomTabs[col],
            left:   col === 0             ? 0 : -lrBounds[col-1],
            right:  col === BOARD_COLS-1  ? 0 :  lrBounds[col],
        };
    }

    // Draw jigsaw piece path on ctx.
    // x,y = top-left of the bounding box, w,h = size
    // sides = {top,right,bottom,left} each -1|0|1
    function jigsawPath(ctx, x, y, w, h, sides) {
        // Left/right tab dimensions (proportional to w)
        const lrTd = w * 0.22; // depth of left/right tabs
        const lrTr = h * 0.16; // radius of left/right tab curve
        const lrTw = h * 0.28; // half-width of left/right tab

        // Top/bottom tab dimensions (proportional to h)
        const tbTd = h * 0.22; // depth of top/bottom tabs
        const tbTr = w * 0.16; // radius of top/bottom tab curve
        const tbTw = w * 0.28; // half-width of top/bottom tab

        ctx.beginPath();

        // Top edge (left to right)
        ctx.moveTo(x, y);
        if (sides.top !== 0) {
            const mx = x + w/2, my = y;
            ctx.lineTo(mx - tbTw, my);
            ctx.bezierCurveTo(mx-tbTw, my - sides.top*tbTd*0.5, mx-tbTr, my - sides.top*tbTd, mx, my - sides.top*tbTd);
            ctx.bezierCurveTo(mx+tbTr, my - sides.top*tbTd, mx+tbTw, my - sides.top*tbTd*0.5, mx+tbTw, my);
            ctx.lineTo(x+w, y);
        } else {
            ctx.lineTo(x+w, y);
        }

        // Right edge (top to bottom)
        if (sides.right !== 0) {
            const mx = x+w, my = y + h/2;
            ctx.lineTo(mx, my - lrTw);
            ctx.bezierCurveTo(mx + sides.right*lrTd*0.5, my-lrTw, mx + sides.right*lrTd, my-lrTr, mx + sides.right*lrTd, my);
            ctx.bezierCurveTo(mx + sides.right*lrTd, my+lrTr, mx + sides.right*lrTd*0.5, my+lrTw, mx, my+lrTw);
            ctx.lineTo(x+w, y+h);
        } else {
            ctx.lineTo(x+w, y+h);
        }

        // Bottom edge (right to left)
        if (sides.bottom !== 0) {
            const mx = x + w/2, my = y+h;
            ctx.lineTo(mx + tbTw, my);
            ctx.bezierCurveTo(mx+tbTw, my + sides.bottom*tbTd*0.5, mx+tbTr, my + sides.bottom*tbTd, mx, my + sides.bottom*tbTd);
            ctx.bezierCurveTo(mx-tbTr, my + sides.bottom*tbTd, mx-tbTw, my + sides.bottom*tbTd*0.5, mx-tbTw, my);
            ctx.lineTo(x, y+h);
        } else {
            ctx.lineTo(x, y+h);
        }

        // Left edge (bottom to top)
        if (sides.left !== 0) {
            const mx = x, my = y + h/2;
            ctx.lineTo(mx, my + lrTw);
            ctx.bezierCurveTo(mx - sides.left*lrTd*0.5, my+lrTw, mx - sides.left*lrTd, my+lrTr, mx - sides.left*lrTd, my);
            ctx.bezierCurveTo(mx - sides.left*lrTd, my-lrTr, mx - sides.left*lrTd*0.5, my-lrTw, mx, my-lrTw);
            ctx.lineTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }

        ctx.closePath();
    }

    // ── Scene drawing ─────────────────────────────────────────────
    // Draws the full scene into ctx, offset so column `sliceIndex` is visible.
    // pieceCanvas=true means we're drawing a small standalone piece (no board context).
    function drawScene(ctx, sliceIndex, w, h) {
        const fullW = w * BOARD_COLS;
        const ox    = sliceIndex * w;

        // Sky
        const sky = ctx.createLinearGradient(0,0,0,h*.7);
        sky.addColorStop(0,T.sky0); sky.addColorStop(1,T.sky1);
        ctx.fillStyle=sky; ctx.fillRect(0,0,w,h);

        // Stars
        if(T.star){
            const sr=seededRand(THEME_INDEX*31+7);
            for(let i=0;i<60;i++){
                const sx=(sr()*fullW)-ox, sy=sr()*h*.62;
                if(sx<-2||sx>w+2) continue;
                const r=sr()*1.2+.3, br=sr()*.6+.4;
                ctx.fillStyle=`rgba(255,255,255,${br})`;
                ctx.beginPath();ctx.arc(sx,sy,r,0,Math.PI*2);ctx.fill();
            }
        }

        const horizonY = h*.62;

        // Moon
        if(T.style==='city'||T.style==='cyber'){
            const mx=(fullW*.15)-ox,my=h*.18;
            if(mx>-30&&mx<w+30){
                const mg=ctx.createRadialGradient(mx,my,0,mx,my,22);
                mg.addColorStop(0,'rgba(200,160,255,.9)');mg.addColorStop(1,'rgba(200,160,255,0)');
                ctx.fillStyle=mg;ctx.beginPath();ctx.arc(mx,my,22,0,Math.PI*2);ctx.fill();
            }
        }
        if(T.style==='aurora'){
            for(let band=0;band<3;band++){
                const by=h*(.15+band*.1),bh2=h*.06;
                const ag=ctx.createLinearGradient(0,by,0,by+bh2);
                ag.addColorStop(0,'rgba(0,220,130,0)');ag.addColorStop(.5,`rgba(0,220,130,${.18-band*.04})`);ag.addColorStop(1,'rgba(0,220,130,0)');
                ctx.fillStyle=ag;
                ctx.beginPath();ctx.moveTo(0,by);
                for(let x=0;x<=w;x+=4)ctx.lineTo(x,by+Math.sin((x+ox+band*80)*.015)*bh2*.6);
                ctx.lineTo(w,by+bh2);ctx.lineTo(0,by+bh2);ctx.closePath();ctx.fill();
            }
        }
        if(T.style==='desert'){
            const sx2=(fullW*.6)-ox,sy2=h*.28;
            if(sx2>-50&&sx2<w+50){
                const sg=ctx.createRadialGradient(sx2,sy2,0,sx2,sy2,40);
                sg.addColorStop(0,'rgba(255,220,80,.9)');sg.addColorStop(.4,'rgba(255,140,30,.5)');sg.addColorStop(1,'rgba(255,60,0,0)');
                ctx.fillStyle=sg;ctx.beginPath();ctx.arc(sx2,sy2,40,0,Math.PI*2);ctx.fill();
            }
        }
        if(T.style==='volcano'){
            const lg=ctx.createRadialGradient(fullW*.5-ox,h*.7,0,fullW*.5-ox,h*.7,h*.5);
            lg.addColorStop(0,'rgba(255,80,0,.25)');lg.addColorStop(1,'rgba(255,80,0,0)');
            ctx.fillStyle=lg;ctx.fillRect(0,0,w,h);
        }
        if(T.style==='cyber'){
            const rainR=seededRand(THEME_INDEX*53+sliceIndex*17);
            ctx.strokeStyle='rgba(255,0,180,.15)';ctx.lineWidth=.8;
            for(let i=0;i<20;i++){const rx=rainR()*w,ry=rainR()*h*.7,rl=rainR()*14+6;ctx.beginPath();ctx.moveTo(rx,ry);ctx.lineTo(rx-1,ry+rl);ctx.stroke();}
        }

        // Horizon glow
        const hg=ctx.createLinearGradient(0,h*.5,0,h*.75);
        hg.addColorStop(0,T.horizon+'00');hg.addColorStop(.5,T.horizon+'55');hg.addColorStop(1,T.horizon+'00');
        ctx.fillStyle=hg;ctx.fillRect(0,0,w,h);

        // Cityscape
        if(T.style==='city'||T.style==='cyber'){
            const br2=seededRand(THEME_INDEX*71+3);
            for(let b=0;b<12;b++){
                const bx=(b/12)*fullW-ox,bw2=br2()*18+10,bh3=br2()*h*.32+h*.08,by3=horizonY-bh3;
                if(bx+bw2<0||bx>w)continue;
                ctx.fillStyle=T.style==='cyber'?'#0a0018':'#080818';ctx.fillRect(bx,by3,bw2,bh3+2);
                const wr2=seededRand(b*19+THEME_INDEX);
                const cols=Math.floor(bw2/5),rows=Math.floor(bh3/7);
                for(let row=0;row<rows;row++)for(let col=0;col<cols;col++){
                    if(wr2()>.45)continue;
                    ctx.fillStyle=T.style==='cyber'?`rgba(255,0,200,${wr2()*.5+.3})`:`rgba(255,220,120,${wr2()*.5+.3})`;
                    ctx.fillRect(bx+col*5+1,by3+row*7+2,3,4);
                }
            }
        }
        // Trees/pines
        if(T.style==='aurora'||T.style==='desert'){
            const tr2=seededRand(THEME_INDEX*43+sliceIndex*11);
            for(let t=0;t<5;t++){
                const tx=(tr2()*fullW)-ox,th2=tr2()*h*.2+h*.12,tw2=th2*.45;
                if(tx+tw2<0||tx-tw2>w)continue;
                ctx.fillStyle=T.style==='desert'?'#1a0800':'#010f05';
                ctx.beginPath();ctx.moveTo(tx,horizonY-th2);ctx.lineTo(tx+tw2,horizonY);ctx.lineTo(tx-tw2,horizonY);ctx.closePath();ctx.fill();
                ctx.beginPath();ctx.moveTo(tx,horizonY-th2*1.1);ctx.lineTo(tx+tw2*.7,horizonY-th2*.45);ctx.lineTo(tx-tw2*.7,horizonY-th2*.45);ctx.closePath();ctx.fill();
            }
        }
        // Volcano
        if(T.style==='volcano'){
            const vx=(fullW*.5)-ox,vw2=fullW*.22,vh2=h*.38;
            if(vx+vw2>0&&vx-vw2<w){
                ctx.fillStyle='#1a0500';ctx.beginPath();ctx.moveTo(vx-vw2,horizonY);ctx.lineTo(vx,horizonY-vh2);ctx.lineTo(vx+vw2,horizonY);ctx.closePath();ctx.fill();
                const lvg=ctx.createRadialGradient(vx,horizonY-vh2,0,vx,horizonY-vh2,20);
                lvg.addColorStop(0,'rgba(255,120,0,.8)');lvg.addColorStop(1,'rgba(255,60,0,0)');
                ctx.fillStyle=lvg;ctx.beginPath();ctx.arc(vx,horizonY-vh2,20,0,Math.PI*2);ctx.fill();
                ctx.strokeStyle='rgba(255,80,0,.6)';ctx.lineWidth=2;
                ctx.beginPath();ctx.moveTo(vx-8,horizonY-vh2+10);ctx.quadraticCurveTo(vx-vw2*.4,horizonY-vh2*.4,vx-vw2*.6,horizonY);ctx.stroke();
                ctx.beginPath();ctx.moveTo(vx+6,horizonY-vh2+14);ctx.quadraticCurveTo(vx+vw2*.35,horizonY-vh2*.35,vx+vw2*.55,horizonY);ctx.stroke();
            }
        }

        // Ground
        const gg=ctx.createLinearGradient(0,horizonY,0,h);
        gg.addColorStop(0,T.horizon+'cc');gg.addColorStop(.3,T.ground);gg.addColorStop(1,'#000');
        ctx.fillStyle=gg;ctx.fillRect(0,horizonY,w,h-horizonY);

        // Ocean ripples
        if(T.style==='ocean'){
            ctx.strokeStyle=T.accent+'22';ctx.lineWidth=.8;
            for(let i=0;i<8;i++){
                const wy=horizonY+i*7+4;ctx.beginPath();
                for(let x=0;x<=w;x+=2){const wave=Math.sin((x+ox+i*23)*.06)*2;if(x===0)ctx.moveTo(x,wy+wave);else ctx.lineTo(x,wy+wave);}
                ctx.stroke();
            }
        }
        // Desert dunes
        if(T.style==='desert'){
            ctx.fillStyle='#2a0e00';ctx.beginPath();ctx.moveTo(0,horizonY+h*.1);
            for(let x=0;x<=w;x+=3)ctx.lineTo(x,horizonY+h*.1+Math.sin((x+ox)*.025)*h*.05+Math.sin((x+ox)*.007)*h*.04);
            ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();ctx.fill();
        }
        // Cyber grid
        if(T.style==='cyber'){
            ctx.strokeStyle='rgba(255,0,180,.1)';ctx.lineWidth=.6;
            for(let i=1;i<5;i++){const gy=horizonY+(h-horizonY)*(i/5);ctx.beginPath();ctx.moveTo(0,gy);ctx.lineTo(w,gy);ctx.stroke();}
        }

        // Foreground glow
        const fg=ctx.createLinearGradient(0,h*.85,0,h);
        fg.addColorStop(0,T.accent+'00');fg.addColorStop(1,T.accent+'18');
        ctx.fillStyle=fg;ctx.fillRect(0,h*.85,w,h*.15);
    }

    // ── Draw a board slot with jigsaw clip ───────────────────────
    // gapNum: 1-3 number to show in gap (0 = not a gap)
    function drawBoardSlot(canvas, col, w, h, isGap, gapNum) {
        canvas.width  = Math.ceil(w + w * 0.22 * 2); // extra space for tabs sticking out
        canvas.height = Math.ceil(h + h * 0.22 * 2);
        const ctx = canvas.getContext('2d');
        const pad = { x: w * 0.22, y: h * 0.22 };

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const sides = slotShape(col);

        if (isGap) {
            // Draw the dark gap indicator
            ctx.save();
            jigsawPath(ctx, pad.x, pad.y, w, h, sides);
            ctx.fillStyle = 'rgba(99,51,255,0.08)';
            ctx.fill();
            // Dashed border
            ctx.strokeStyle = 'rgba(99,51,255,0.5)';
            ctx.lineWidth = 1.5;
            ctx.setLineDash([4,3]);
            ctx.stroke();
            ctx.setLineDash([]);
            ctx.restore();

        } else {
            // Clip to jigsaw shape, then draw scene
            ctx.save();
            jigsawPath(ctx, pad.x, pad.y, w, h, sides);
            ctx.clip();

            // Offset scene so the tab areas contain the correct scene pixels
            ctx.translate(pad.x - col * w, pad.y);
            drawScene(ctx, 0, w * BOARD_COLS, h); // draw full scene, translated
            ctx.restore();

            // Subtle edge highlight
            ctx.save();
            jigsawPath(ctx, pad.x, pad.y, w, h, sides);
            ctx.strokeStyle = 'rgba(255,255,255,0.08)';
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.restore();
        }
    }

    // ── Draw a draggable piece ────────────────────────────────────
    // pieceNum: 1-3 number to show on piece
    function drawPieceCanvas(canvas, pieceIndex, w, h, pieceNum) {
        const col   = MISSING_SLOTS[pieceIndex];
        const sides = slotShape(col);

        // Canvas size includes tab overhang
        canvas.width  = Math.ceil(w + w * 0.22 * 2);
        canvas.height = Math.ceil(h + h * 0.22 * 2);
        const ctx = canvas.getContext('2d');
        const pad = { x: w * 0.22, y: h * 0.22 };

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Clip to jigsaw shape
        ctx.save();
        jigsawPath(ctx, pad.x, pad.y, w, h, sides);
        ctx.clip();

        // Draw scene offset so this col's content is visible
        ctx.translate(pad.x - col * w, pad.y);
        drawScene(ctx, 0, w * BOARD_COLS, h);
        ctx.restore();

        // Outline
        ctx.save();
        jigsawPath(ctx, pad.x, pad.y, w, h, sides);
        ctx.strokeStyle = 'rgba(99,51,255,0.7)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.restore();

    }

    // ── State ─────────────────────────────────────────────────────
    const placed      = {}; // slotIndex => pieceIndex
    const orderedAns  = []; // filled in placement order: [{piece, slot, tray_label}, ...]
    let   dragging    = null;
    let   placedCount = 0;
    let   nextExpectedLabel = 1; // which tray label must be placed next (1, then 2, then 3)

    function markPuzzleInteracted() {
        const el = document.getElementById('puzzleInteracted');
        if (el) el.value = '1';
    }

    // ── Build UI ──────────────────────────────────────────────────
    const board    = document.getElementById('puzzleBoard');
    const tray     = document.getElementById('pieceTray');
    const ghost    = document.getElementById('draggingGhost');
    const ghostCvs = document.getElementById('ghostCanvas');

    let SLOT_W = 0, SLOT_H = 0;

    function buildBoard() {
        board.innerHTML = '';
        const boardW = board.offsetWidth || 500;
        SLOT_W = Math.floor(boardW / BOARD_COLS);
        SLOT_H = board.offsetHeight || 130;

        for (let col = 0; col < BOARD_COLS; col++) {
            const slot = document.createElement('div');
            slot.className = 'board-slot';
            slot.dataset.col = col;

            const cvs = document.createElement('canvas');
            slot.appendChild(cvs);
            board.appendChild(slot);

            const isGap   = MISSING_SLOTS.includes(col) && !placed.hasOwnProperty(col);
            // gapNum: use the tray display position of the piece that belongs here,
            // so the number on the gap matches the number shown on the draggable piece.
            // TRAY_ORDER = shuffled piece indices, piece label = tray position + 1.
            const pieceIdxForSlot = MISSING_SLOTS.indexOf(col);
            const trayPos  = pieceIdxForSlot >= 0 ? TRAY_ORDER.indexOf(pieceIdxForSlot) : -1;
            const gapNum   = isGap && trayPos >= 0 ? (trayPos + 1) : 0;
            requestAnimationFrame(() => {
                cvs.style.width  = slot.offsetWidth  + 'px';
                cvs.style.height = slot.offsetHeight + 'px';
                drawBoardSlot(cvs, col, slot.offsetWidth, slot.offsetHeight, isGap, gapNum);
            });

            // Drop target overlay
            const dt = document.createElement('div');
            dt.className = 'drop-target' + (MISSING_SLOTS.includes(col) && !placed.hasOwnProperty(col) ? ' active' : '');
            dt.dataset.col = col;
            slot.appendChild(dt);

            if (MISSING_SLOTS.includes(col)) {
                dt.addEventListener('dragover',  e => { e.preventDefault(); if(!placed.hasOwnProperty(col)) dt.classList.add('drag-over'); });
                dt.addEventListener('dragleave', () => dt.classList.remove('drag-over'));
                dt.addEventListener('drop',      e => { e.preventDefault(); dt.classList.remove('drag-over'); handleDrop(col, dt, cvs); });
            }
        }
    }

    function buildTray() {
        tray.innerHTML = '';
        TRAY_ORDER.forEach(pieceIdx => {
            const slotCol = MISSING_SLOTS[pieceIdx]; // actual correct board slot for this piece
            const wrap = document.createElement('div');
            wrap.className = 'piece-wrap';
            wrap.dataset.piece = pieceIdx;
            wrap.draggable = true;
            if (Object.values(placed).includes(pieceIdx)) wrap.classList.add('used');

            const cWrap = document.createElement('div');
            cWrap.className = 'piece-canvas-wrap';
            const cvs = document.createElement('canvas');
            cWrap.appendChild(cvs);
            wrap.appendChild(cWrap);

            const lbl = document.createElement('div');
            lbl.className = 'piece-label';
            const pieceNum = TRAY_ORDER.indexOf(pieceIdx) + 1;
            lbl.textContent = 'piece ' + pieceNum;
            wrap.appendChild(lbl);
            tray.appendChild(wrap); // tray position label, matches gap number
            requestAnimationFrame(() => {
                drawPieceCanvas(cvs, pieceIdx, cWrap.offsetWidth, cWrap.offsetHeight, pieceNum);
                drawPieceCanvas(ghostCvs, pieceIdx, cWrap.offsetWidth, cWrap.offsetHeight, pieceNum);
            });

            // Desktop drag
            wrap.addEventListener('dragstart', e => {
                markPuzzleInteracted();
                dragging = { pieceIndex: pieceIdx, el: wrap };
                e.dataTransfer.setData('text/plain', pieceIdx);
                e.dataTransfer.effectAllowed = 'move';
                // Show active drop targets
                document.querySelectorAll('.drop-target').forEach(dt => {
                    const col = parseInt(dt.dataset.col);
                    if (MISSING_SLOTS.includes(col) && !placed.hasOwnProperty(col)) {
                        dt.classList.add('active');
                    }
                });
                requestAnimationFrame(() => {
                    drawPieceCanvas(ghostCvs, pieceIdx, cWrap.offsetWidth, cWrap.offsetHeight, pieceIdx + 1);
                });
            });
            wrap.addEventListener('dragend', () => {
                dragging = null;
                document.querySelectorAll('.drop-target').forEach(dt => dt.classList.remove('drag-over'));
            });

            // Touch drag
            wrap.addEventListener('touchstart', e => {
                if (wrap.classList.contains('used')) return;
                markPuzzleInteracted();
                dragging = { pieceIndex: pieceIdx, el: wrap };
                ghost.style.display = 'block';
                ghost.style.width  = cWrap.offsetWidth  + 'px';
                ghost.style.height = cWrap.offsetHeight + 'px';
                requestAnimationFrame(() => drawPieceCanvas(ghostCvs, pieceIdx, cWrap.offsetWidth, cWrap.offsetHeight, pieceIdx + 1));
                movGhost(e.touches[0]);
                document.querySelectorAll('.drop-target').forEach(dt => {
                    const col = parseInt(dt.dataset.col);
                    if (MISSING_SLOTS.includes(col) && !placed.hasOwnProperty(col)) dt.classList.add('active');
                });
            }, {passive:true});
        });
    }

    // ── Handle a drop onto a slot ─────────────────────────────────
    function handleDrop(slotCol, dropTarget, slotCanvas) {
        if (dragging === null) return;
        const pieceIdx  = dragging.pieceIndex;
        const trayLabel = TRAY_ORDER.indexOf(pieceIdx) + 1; // 1, 2, or 3

        // Enforce order — must place tray label 1 first, then 2, then 3
        if (trayLabel !== nextExpectedLabel) {
            dropTarget.classList.add('wrong');
            showOrderHint(nextExpectedLabel);
            setTimeout(() => dropTarget.classList.remove('wrong'), 700);
            return;
        }

        // Validate correct slot
        const correctCol = MISSING_SLOTS[pieceIdx];
        if (slotCol !== correctCol) {
            dropTarget.classList.add('wrong');
            setTimeout(() => dropTarget.classList.remove('wrong'), 700);
            return;
        }

        // Correct placement in correct order!
        placed[slotCol] = pieceIdx;
        orderedAns.push({ piece: pieceIdx, slot: slotCol, tray_label: trayLabel });
        placedCount++;
        nextExpectedLabel++;

        // Mark piece as used
        dragging.el.classList.add('used');

        // Update progress dot
        document.getElementById('dot' + (trayLabel - 1)).classList.add('done');

        // Redraw slot with the filled piece
        requestAnimationFrame(() => {
            drawBoardSlot(slotCanvas, slotCol, slotCanvas.offsetWidth || SLOT_W, slotCanvas.offsetHeight || SLOT_H, false, 0);
        });

        // Remove active drop target
        dropTarget.classList.remove('active','drag-over');
        dropTarget.style.pointerEvents = 'none';
        dropTarget.classList.add('filled');

        dragging = null;

        // All 3 placed?
        if (placedCount === 3) {
            setTimeout(submitAll, 400);
        }
    }

    function submitAll() {
        document.getElementById('answersInput').value = JSON.stringify(orderedAns);
        document.getElementById('successFlash').style.display = 'flex';
        setTimeout(() => document.getElementById('verify-form').submit(), 500);
    }

    // Show a brief hint when wrong order is attempted
    function showOrderHint(expected) {
        let hint = document.getElementById('orderHint');
        if (!hint) {
            hint = document.createElement('div');
            hint.id = 'orderHint';
            hint.style.cssText = 'position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:rgba(220,50,80,0.92);color:#fff;padding:10px 20px;border-radius:10px;font-size:.82rem;font-family:Inter,sans-serif;z-index:9999;pointer-events:none;transition:opacity .3s';
            document.body.appendChild(hint);
        }
        hint.textContent = 'Place piece ' + expected + ' next!';
        hint.style.opacity = '1';
        clearTimeout(hint._t);
        hint._t = setTimeout(() => { hint.style.opacity = '0'; }, 1800);
    }

    buildBoard();
    buildTray();

    // ── Touch move / end (global) ─────────────────────────────────
    document.addEventListener('touchmove', e => {
        if (!dragging) return;
        e.preventDefault();
        movGhost(e.touches[0]);
        document.querySelectorAll('.drop-target.active').forEach(dt => {
            const r = dt.getBoundingClientRect();
            const t = e.touches[0];
            dt.classList.toggle('drag-over', t.clientX>=r.left&&t.clientX<=r.right&&t.clientY>=r.top&&t.clientY<=r.bottom);
        });
    }, {passive:false});

    document.addEventListener('touchend', e => {
        if (!dragging) return;
        ghost.style.display = 'none';
        const t = e.changedTouches[0];
        const el = document.elementFromPoint(t.clientX, t.clientY);
        const dt = el ? el.closest('.drop-target.active') : null;
        if (dt) {
            const col = parseInt(dt.dataset.col);
            const slot = board.querySelector(`.board-slot[data-col="${col}"]`);
            const cvs  = slot ? slot.querySelector('canvas') : null;
            if (cvs) handleDrop(col, dt, cvs);
        }
        document.querySelectorAll('.drop-target').forEach(d => d.classList.remove('drag-over'));
        dragging = null;
    });

    function movGhost(t) { ghost.style.left=t.clientX+'px'; ghost.style.top=t.clientY+'px'; }

    window.addEventListener('resize', () => { buildBoard(); buildTray(); });
})();
</script>
</body>
</html>
<?php exit; ?>
