<?php
// ---------- security headers (help against XSS) ----------
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

// ---------- tiny helper ----------
function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

// ---------- database (SQLite file in same folder) ----------
$db = new PDO('sqlite:' . __DIR__ . '/results.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec("CREATE TABLE IF NOT EXISTS results(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  s1 INTEGER NOT NULL, s2 INTEGER NOT NULL, s3 INTEGER NOT NULL,
  s4 INTEGER NOT NULL, s5 INTEGER NOT NULL,
  total INTEGER NOT NULL, percentage REAL NOT NULL
)");

$errors = [];
$result = null;
$old = ['name'=>'','s1'=>'','s2'=>'','s3'=>'','s4'=>'','s5'=>''];

// ---------- handle submit ----------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // trim & keep for re-fill
  foreach ($old as $k => $_) { $old[$k] = isset($_POST[$k]) ? trim($_POST[$k]) : ''; }

  // 1) input validation (server-side)
  if (!preg_match("/^[A-Za-z][A-Za-z\s\.\'\-]{1,49}$/", $old['name'])) {
    $errors[] = "Name: letters/spaces/.'- only, 2–50 chars.";
  }
  $marks = [];
  for ($i=1; $i<=5; $i++) {
    if ($old["s$i"] === '' || !ctype_digit($old["s$i"])) {
      $errors[] = "Subject $i: enter an integer 0–100.";
    } else {
      $val = (int)$old["s$i"];
      if ($val < 0 || $val > 100) $errors[] = "Subject $i must be 0–100.";
      $marks[] = $val;
    }
  }

  if (!$errors) {
    $total = array_sum($marks);
    $percentage = round($total/5, 2);

    // 2) SQL Injection mitigation: prepared statement with bound params
    $stmt = $db->prepare("INSERT INTO results(name,s1,s2,s3,s4,s5,total,percentage)
                          VALUES(?,?,?,?,?,?,?,?)");
    $stmt->execute([$old['name'],$marks[0],$marks[1],$marks[2],$marks[3],$marks[4],$total,$percentage]);

    $result = [
      'name' => $old['name'],        // will be HTML-escaped when printed
      'total' => $total,
      'percentage' => $percentage
    ];

    // clear form
    $old = ['name'=>'','s1'=>'','s2'=>'','s3'=>'','s4'=>'','s5'=>''];
  }
}

// last 5 rows for quick proof it saved
$rows = $db->query("SELECT id,name,total,percentage FROM results ORDER BY id DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Marks Calculator (Secure One-Pager)</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font-family:system-ui,Arial,sans-serif;max-width:800px;margin:32px auto;padding:0 16px}
  h1{margin-top:0}
  form{display:grid;gap:10px}
  .row{display:grid;grid-template-columns:160px 1fr;gap:8px;align-items:center}
  input{padding:8px;border:1px solid #ccc;border-radius:8px}
  .btn{padding:10px 16px;border:0;border-radius:10px;background:#1b73e8;color:#fff;cursor:pointer}
  .err{background:#ffecec;color:#8a0000;border:1px solid #ffb3b3;padding:8px 12px;border-radius:8px}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th,td{border:1px solid #ddd;padding:8px} th{background:#f5f5f5;text-align:left}
  small{color:#666}
</style>
</head>
<body>
  <h1>Student Marks (5 Subjects)</h1>

  <?php if ($errors): ?>
    <?php foreach ($errors as $e): ?><div class="err"><?= e($e) ?></div><?php endforeach; ?>
  <?php endif; ?>

  <form method="post" novalidate>
    <div class="row"><label>Student name</label>
      <input name="name" value="<?= e($old['name']) ?>" maxlength="50"
             pattern="^[A-Za-z][A-Za-z\s\.'-]{1,49}$" required>
    </div>
    <?php for($i=1;$i<=5;$i++): ?>
      <div class="row"><label>Subject <?= $i ?> (0–100)</label>
        <input type="number" name="s<?= $i ?>" value="<?= e($old["s$i"]) ?>" min="0" max="100" step="1" required>
      </div>
    <?php endfor; ?>
    <button class="btn" type="submit">Calculate</button>
    <small>Client checks help, but real protection is on the server.</small>
  </form>

  <?php if ($result): ?>
    <h2>Result</h2>
    <!-- 3) XSS mitigation: we ALWAYS escape dynamic output with htmlspecialchars via e() -->
    <p><strong>Student:</strong> <?= e($result['name']) ?></p>
    <p><strong>Total (out of 500):</strong> <?= e($result['total']) ?></p>
    <p><strong>Percentage:</strong> <?= e($result['percentage']) ?>%</p>
  <?php endif; ?>

  <h2>Recent Saves (Proof)</h2>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Total</th><th>Percentage</th></tr></thead>
    <tbody>
      <?php foreach($rows as $r): ?>
        <tr>
          <td><?= e($r['id']) ?></td>
          <td><?= e($r['name']) ?></td>
          <td><?= e($r['total']) ?></td>
          <td><?= e($r['percentage']) ?>%</td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>

  <p><small>Security used: server-side validation, parameterized SQL (PDO prepare/execute), output encoding (htmlspecialchars), CSP headers.</small></p>
</body>
</html>
