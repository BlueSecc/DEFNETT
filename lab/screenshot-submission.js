// Ambil 5 screenshot submission dari dashboard lab VM lewat HTTPS asli.
// CA lab harus dipercaya macOS; verifikasi sertifikat tidak dimatikan.
// Kata sandi operator dibaca dari stdin, tidak dicetak dan tidak disimpan.
// Pemakaian (dari root repo):
//   read -rs P; printf '%s' "$P" | node lab/screenshot-submission.js; unset P
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const BASE = process.env.DEFNETT_URL || 'https://192.168.56.20:8443/';
const USER = process.env.DEFNETT_USER || 'admin';
const HOST = 'server-a';
const OUT = path.join(__dirname, 'screenshots', 'submission');

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')));
  });
}

(async () => {
  const password = await readStdin();
  if (!password) throw new Error('kata sandi kosong');
  fs.mkdirSync(OUT, { recursive: true });

  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const context = await browser.newContext({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const state = () => page.evaluate(async () => (await fetch('/v1/dashboard', { cache: 'no-store' })).json());
  const waitFor = async (predicate, ms, label) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      try { if (await predicate()) return; } catch (error) { /* coba lagi */ }
      await page.waitForTimeout(500);
    }
    throw new Error(`waktu habis menunggu ${label}`);
  };
  const shot = async (name) => {
    await page.screenshot({ path: path.join(OUT, name) });
    console.log('tersimpan', path.join('lab/screenshots/submission', name));
  };

  try {
    await page.goto(BASE, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#operator-modal:not([hidden])', { timeout: 15000 });
    await page.fill('#op-user', USER);
    await page.fill('#op-pass', password);
    await page.evaluate(() => { document.getElementById('op-error').textContent = ''; });
    await page.click('#op-login');
    await page.waitForFunction(
      () => document.getElementById('operator-modal').hidden || document.getElementById('op-error').textContent.trim(),
      null, { timeout: 15000 },
    );
    const loginError = (await page.textContent('#op-error')).trim();
    if (!(await page.isHidden('#operator-modal'))) throw new Error(`login ditolak: ${loginError || 'tanpa pesan'}`);

    await waitFor(async () => Object.values((await state()).backends).every((v) => v === 'UP'), 60000, 'semua backend UP');
    await page.waitForTimeout(3000);
    await shot('01-overview.png');

    await page.click('#tab-patrol');
    await page.waitForTimeout(3000);
    await page.selectOption('#patrol-incident-host', HOST);
    await page.click('#attack-vector button[data-vector="ssh"]');
    await page.waitForSelector('#patrol-incident-demo:not([disabled])', { timeout: 30000 });
    await page.click('#patrol-incident-demo');
    await page.waitForTimeout(4500);
    await shot('02-serangan-masuk.png');

    if (!(await page.isVisible('.s-tab[data-target="s-playbook"]'))) await page.click('#sidebar-open');
    await page.click('.s-tab[data-target="s-playbook"]');
    const approve = page.locator('#approval-list li', { hasText: `Pulihkan kunci dari master · ${HOST}` })
      .locator('button', { hasText: 'Setujui' }).first();
    await approve.waitFor({ timeout: 60000 });
    await page.waitForTimeout(800);
    await shot('03-persetujuan.png');

    await approve.click();
    await waitFor(async () => (await state()).backends[HOST] !== 'UP', 20000, 'server terisolasi');
    await page.waitForTimeout(2500);
    await shot('04-terisolasi.png');

    await waitFor(async () => {
      const s = await state();
      return s.backends[HOST] === 'UP' && s.remediation && s.remediation.status === 'REPAIRED';
    }, 90000, 'server pulih');
    await page.waitForTimeout(3000);
    await shot('05-pulih-metrik.png');
  } finally {
    try { await page.click('#operator-button', { timeout: 3000 }); } catch (error) { /* sesi sudah habis */ }
    await browser.close();
  }
})().catch((error) => {
  console.error('gagal:', error.message);
  process.exit(1);
});
