'use strict';
/**
 * TechNova - máy chủ (backend) Node.js + Express + SQLite
 * Chạy:  npm start   →  http://localhost:3000   (điện thoại cùng Wi-Fi: http://<IP máy tính>:3000)
 *
 * Backend là nơi DUY NHẤT giữ dữ liệu thật và quyết định:
 *  - ai đã đăng nhập (phiên cookie HttpOnly), ai là admin
 *  - giá, Flash Sale, mã giảm giá, tổng tiền của đơn hàng (không tin giá do trình duyệt gửi)
 *  - hủy đơn / đổi trạng thái / sửa sản phẩm chỉ khi đúng quyền
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');
const vnpay = require('./vnpay');
const { openDatabase, seedIfEmpty, seedProducts, insertProduct, seedFlashSales, makeClock, hashPassword, verifyPassword, DUMMY_HASH, FLASH_SLOT_HOURS, pad2 } = require('./db');

// ======================= Hằng số & tiện ích =======================
const MAX_FAILS = 5, LOCK_BASE_S = 60, LOCK_MAX_S = 900;
const IDLE_USER_MS = 30 * 60 * 1000, IDLE_ADMIN_MS = 15 * 60 * 1000, SESSION_MAX_MS = 7 * 24 * 3600 * 1000;
const COOKIE = 'tn_sid';
const PAYMENTS = ['Thanh toán khi nhận hàng (COD)', 'Chuyển khoản ngân hàng (VietQR)', 'Thẻ tín dụng / VNPAY'];
const ORDER_STATUSES = ['Chờ xác nhận', 'Đang giao hàng', 'Đã giao thành công', 'Đã hủy'];
const ORDER_RANK = { 'Chờ xác nhận': 0, 'Đang giao hàng': 1, 'Đã giao thành công': 2, 'Đã hủy': 2 };
const COUPONS = [
    { code: 'GIAM200K', type: 'fixed', value: 200000, min: 2000000 },
    { code: 'TECHNOVA10', type: 'percent', value: 10, max: 500000, min: 5000000 },
    { code: 'NEWUSER', type: 'percent', value: 15, max: 1000000, min: 0, firstOrderOnly: true },
    { code: 'BLACKFRIDAY', type: 'percent', value: 20, max: 2000000, min: 10000000, expires: '2026-11-30' }
];
const COMMON_PASSWORDS = ['12345678', '123456789', '1234567890', 'password', 'password1', 'matkhau123', 'qwerty123', 'abc12345', 'admin123', 'iloveyou1', '11111111', '00000000', 'technova1', 'technova123'];

const stripControl = s => String(s == null ? '' : s).replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E]/g, '');
const cleanText = (s, max = 200) => stripControl(s).replace(/\s+/g, ' ').trim().slice(0, max);
const cleanName = s => stripControl(s).replace(/[^\p{L}\p{M} '.\-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, 50);
const normPhone = s => { const d = String(s || '').replace(/\D/g, ''); return d.length === 9 && d[0] !== '0' ? '0' + d : d; };   // 912345678 → 0912345678
const validPhone = s => /^0\d{9}$/.test(String(s));
const PHONE_ERR = 'Số điện thoại không hợp lệ';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const validEmail = s => s.length <= 100 && EMAIL_RE.test(s);
const validBirthday = (s, todayStr) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z')) && s >= '1900-01-01' && s <= todayStr;
const GENDERS = ['Nam', 'Nữ', 'Khác'];
const IMG_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'bmp'];
const IMG_ERR = 'Định dạng hình ảnh không hợp lệ, vui lòng chọn file ảnh';
const STOCK_ERR = 'Số lượng sản phẩm vượt quá tồn kho';
const CANCEL_REASONS = ['Không còn nhu cầu mua sản phẩm', 'Đặt nhầm sản phẩm', 'Muốn đổi địa chỉ / thông tin nhận hàng', 'Tìm được giá tốt hơn', 'Lý do khác'];
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

function passwordPolicyError(pw, username) {
    const p = String(pw || '');
    if (p.length < 8) return 'Mật khẩu tối thiểu 8 ký tự.';
    if (p.length > 64) return 'Mật khẩu tối đa 64 ký tự.';
    if (!/\p{L}/u.test(p) || !/\d/.test(p)) return 'Mật khẩu phải có cả chữ và số.';
    if (/\s/.test(p)) return 'Mật khẩu không được chứa khoảng trắng.';
    if (username && username.length >= 3 && p.toLowerCase().includes(username.toLowerCase())) return 'Mật khẩu không được chứa tên đăng nhập.';
    if (COMMON_PASSWORDS.includes(p.toLowerCase())) return 'Mật khẩu quá phổ biến, hãy chọn mật khẩu khác.';
    if (/^(.)\1+$/.test(p)) return 'Mật khẩu không được lặp một ký tự.';
    return '';
}

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = (msg, status = 400) => new HttpError(status, msg);

// Giới hạn tần suất trong bộ nhớ (cho mỗi khóa: IP hoặc tài khoản)
function makeLimiter(nowFn) {
    const buckets = new Map();
    return function limit(key, max, windowMs) {
        const now = nowFn();
        const arr = (buckets.get(key) || []).filter(t => now - t < windowMs);
        if (arr.length >= max) { buckets.set(key, arr); return false; }
        arr.push(now); buckets.set(key, arr);
        if (buckets.size > 5000) for (const [k, v] of buckets) if (!v.length || now - v[v.length - 1] > 3600000) buckets.delete(k);
        return true;
    };
}

// ======================= Tạo ứng dụng =======================
function createApp(options = {}) {
    const nowFn = options.now || (() => Date.now());
    const clock = makeClock(nowFn);
    const db = openDatabase(options.dbFile || path.join(__dirname, 'data', 'technova.db'));
    const limit = makeLimiter(nowFn);
    const uploadDir = options.uploadDir || path.join(__dirname, 'data', 'uploads');
    const app = express();
    app.disable('x-powered-by');
    if (options.trustProxy) app.set('trust proxy', 1);

    const ready = seedIfEmpty(db, clock, { adminPassword: options.adminPassword, customerPassword: options.customerPassword });

    // ---------- Nhật ký bảo mật ----------
    const logStmt = db.prepare('INSERT INTO SecurityLog (ts, type, username, detail, ip) VALUES (?,?,?,?,?)');
    function logSec(type, username, detail, ip) {
        try {
            logStmt.run(nowFn(), type, cleanText(username || '', 30), cleanText(detail || '', 160), ip || '');
            db.prepare('DELETE FROM SecurityLog WHERE id <= (SELECT MAX(id) FROM SecurityLog) - 1000').run();
        } catch (e) { /* không để lỗi log làm hỏng request */ }
    }

    // ---------- Header bảo mật ----------
    app.use((req, res, next) => {
        res.setHeader('Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
            "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self'; " +
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
        next();
    });

    const smallJson = express.json({ limit: '200kb', strict: true });
    app.use((req, res, next) => req.path === '/api/admin/upload' ? next() : smallJson(req, res, next));

    // ---------- Chống CSRF: chỉ nhận request ghi từ chính trang này ----------
    app.use('/api', (req, res, next) => {
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
        const origin = req.headers.origin;
        if (origin) { let host = ''; try { host = new URL(origin).host; } catch (e) {} if (host !== req.headers.host) return res.status(403).json({ ok: false, error: 'Nguồn yêu cầu không hợp lệ.' }); }
        if (req.headers['x-requested-with'] !== 'technova') return res.status(403).json({ ok: false, error: 'Yêu cầu không hợp lệ.' });
        next();
    });
    // Giới hạn chung theo IP
    app.use('/api', (req, res, next) => {
        if (!limit('ip:' + req.ip, 600, 60000)) return res.status(429).json({ ok: false, error: 'Bạn thao tác quá nhanh, vui lòng thử lại sau ít phút.' });
        next();
    });

    // ---------- Phiên đăng nhập (cookie HttpOnly) ----------
    function parseCookies(req) {
        const out = {};
        String(req.headers.cookie || '').split(';').forEach(part => {
            const i = part.indexOf('=');
            if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
        });
        return out;
    }
    function setSessionCookie(req, res, token, maxAgeMs) {
        const secure = req.secure || options.cookieSecure ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure}`);
    }
    const userByName = db.prepare('SELECT username, full_name, email, phone, birthday, gender, role, password_hash FROM Users WHERE username = ?');
    const userByLogin = db.prepare('SELECT username, full_name, email, phone, birthday, gender, role, password_hash FROM Users WHERE username = ? OR email = ? LIMIT 1');
    app.use((req, res, next) => {
        req.user = null;
        const token = parseCookies(req)[COOKIE];
        if (!token || token.length < 32) return next();
        const id = sha256(token);
        const s = db.prepare('SELECT * FROM Sessions WHERE id = ?').get(id);
        if (!s) return next();
        const u = userByName.get(s.username);
        const now = nowFn();
        const idleLimit = u && u.role === 'admin' ? IDLE_ADMIN_MS : IDLE_USER_MS;
        if (!u || now - s.last_active > idleLimit || now - s.created_at > SESSION_MAX_MS) {
            db.prepare('DELETE FROM Sessions WHERE id = ?').run(id);
            if (u) logSec('timeout', u.username, 'Phiên hết hạn do không hoạt động', req.ip);
            req.sessionExpired = true;
            return next();
        }
        // request nền (tự làm mới dữ liệu) không được tính là hoạt động của người dùng
        if (now - s.last_active > 15000 && !req.headers['x-background']) db.prepare('UPDATE Sessions SET last_active = ? WHERE id = ?').run(now, id);
        req.user = { username: u.username, fullName: u.full_name, email: u.email || '', phone: u.phone, birthday: u.birthday || '', gender: u.gender || '', role: u.role };
        req.sessionId = id;
        next();
    });
    const needUser = (req, res, next) => req.user ? next() : res.status(401).json({ ok: false, error: 'Vui lòng đăng nhập.', code: 'unauthenticated', expired: !!req.sessionExpired });
    const needAdmin = (req, res, next) => {
        if (!req.user) return res.status(401).json({ ok: false, error: 'Vui lòng đăng nhập.', code: 'unauthenticated', expired: !!req.sessionExpired });
        if (req.user.role !== 'admin') { logSec('denied', req.user.username, `Bị chặn: ${req.method} ${req.originalUrl}`.slice(0, 150), req.ip); return res.status(403).json({ ok: false, error: 'Bạn không có quyền thực hiện thao tác này.' }); }
        next();
    };
    const adminLog = (req, text) => logSec('admin', req.user.username, text, req.ip);

    function newSession(req, res, username) {
        const token = crypto.randomBytes(32).toString('hex');
        const now = nowFn();
        db.prepare('INSERT INTO Sessions (id, username, created_at, last_active) VALUES (?,?,?,?)').run(sha256(token), username, now, now);
        db.prepare('DELETE FROM Sessions WHERE username = ? AND id NOT IN (SELECT id FROM Sessions WHERE username = ? ORDER BY last_active DESC LIMIT 5)').run(username, username);
        setSessionCookie(req, res, token, SESSION_MAX_MS);
    }
    const publicUser = u => ({ username: u.username, fullName: u.fullName, email: u.email || '', phone: u.phone, birthday: u.birthday || '', gender: u.gender || '', role: u.role });
    const rowToMe = u => publicUser({ username: u.username, fullName: u.full_name, email: u.email, phone: u.phone, birthday: u.birthday, gender: u.gender, role: u.role });

    // ======================= Dữ liệu & Flash Sale =======================
    const rowToProduct = r => ({ id: r.id, name: r.name, category: r.category, price: r.price, oldPrice: r.old_price, discount: r.discount, specs: r.specs, image: r.image, description: r.description, stock: r.stock, active: r.active ? 1 : 0 });
    const allProducts = () => db.prepare('SELECT * FROM Products ORDER BY id').all().map(rowToProduct);
    const allFlashRaw = () => db.prepare('SELECT * FROM FlashSales ORDER BY id').all().map(r => ({ id: r.id, productId: r.product_id, slot: r.slot, flashPrice: r.flash_price, qty: r.qty, soldRaw: r.sold, soldDate: r.sold_date }));
    // Số suất đã bán chỉ tính cho ngày hôm nay; khung giờ chưa mở thì luôn là 0
    const soldNow = d => (d.slot > clock.slot() ? 0 : (d.soldDate === clock.today() ? d.soldRaw : 0));
    const remaining = d => Math.max(0, d.qty - soldNow(d));
    const publicFlash = d => ({ id: d.id, productId: d.productId, slot: d.slot, flashPrice: d.flashPrice, qty: d.qty, sold: soldNow(d), soldDate: clock.today() });
    function liveFlash(prod, flashList) {
        const slot = clock.slot();
        return flashList.find(d => d.productId === prod.id && d.slot === slot && remaining(d) > 0 && d.flashPrice < prod.price) || null;
    }
    function flashLock(prod, flashList) {
        if (liveFlash(prod, flashList)) return null;
        const cur = clock.slot();
        const up = flashList.filter(d => d.productId === prod.id && d.slot > cur && remaining(d) > 0 && d.flashPrice < prod.price).sort((a, b) => a.slot - b.slot)[0];
        return up ? { slot: up.slot, time: pad2(up.slot * FLASH_SLOT_HOURS) + ':00' } : null;
    }
    function releaseFlash(orderId) {
        const items = db.prepare('SELECT * FROM OrderItems WHERE order_id = ? AND flash_id IS NOT NULL').all(orderId);
        items.forEach(it => {
            const d = db.prepare('SELECT * FROM FlashSales WHERE id = ?').get(it.flash_id);
            if (d && d.sold_date === it.flash_day) db.prepare('UPDATE FlashSales SET sold = MAX(0, sold - ?) WHERE id = ?').run(it.qty, d.id);
        });
    }

    function ordersFor(username) {
        const rows = username == null
            ? db.prepare('SELECT * FROM Orders ORDER BY created_ms DESC, rowid DESC').all()
            : db.prepare('SELECT * FROM Orders WHERE username = ? ORDER BY created_ms DESC, rowid DESC').all(username);
        const itemsStmt = db.prepare('SELECT name, qty, price, flash_id, flash_day, product_id FROM OrderItems WHERE order_id = ? ORDER BY id');
        const imgById = db.prepare('SELECT id, image FROM Products WHERE id = ?'), imgByName = db.prepare('SELECT id, image FROM Products WHERE name = ?');
        return rows.map(o => ({
            id: o.id, username: o.username, customerName: o.customer_name, phone: o.phone, address: o.address, date: o.date_str,
            payment: o.payment, status: o.status, subtotal: o.subtotal, discount: o.discount, coupon: o.coupon, total: o.total,
            demo: !!o.is_demo, cancelReason: o.cancel_reason || '', payStatus: o.pay_status || 'unpaid', paidAt: o.paid_at || '',
            items: itemsStmt.all(o.id).map(i => {
                const pr = (i.product_id ? imgById.get(i.product_id) : null) || imgByName.get(i.name);
                return { name: i.name, qty: i.qty, price: i.price, flashId: i.flash_id, flashDay: i.flash_day, productId: pr ? pr.id : null, image: pr ? pr.image : '' };
            })
        }));
    }
    function reviewsMap() {
        const map = {};
        db.prepare('SELECT * FROM Reviews ORDER BY ts, rowid').all().forEach(r => {
            (map[r.product_id] = map[r.product_id] || []).push({ id: r.id, user: r.user_name, rating: r.rating, ts: r.ts, comment: r.comment, verified: !!r.verified, helpful: 0, reply: null });
        });
        return map;
    }
    const addressesFor = username => db.prepare('SELECT id, recipient, phone, detail, district, province, is_default AS isDefault FROM Addresses WHERE username = ? ORDER BY is_default DESC, id').all(username).map(a => ({ ...a, isDefault: !!a.isDefault }));
    function restoreStock(orderId) {
        db.prepare('SELECT product_id, qty FROM OrderItems WHERE order_id = ? AND product_id IS NOT NULL').all(orderId)
            .forEach(i => db.prepare('UPDATE Products SET stock = stock + ? WHERE id = ?').run(i.qty, i.product_id));
    }
    const cartFor = username => db.prepare('SELECT c.product_id AS id, c.qty FROM Carts c JOIN Products p ON p.id = c.product_id WHERE c.username = ? AND p.active = 1 ORDER BY c.rowid').all(username);

    // ======================= API công khai =======================
    const api = express.Router();
    app.use('/api', api);

    api.get('/bootstrap', (req, res) => {
        const isAdmin = !!(req.user && req.user.role === 'admin');
        const products = allProducts().filter(p => p.active || isAdmin);          // khách không thấy sản phẩm đã ngừng kinh doanh
        const visible = new Set(products.map(p => p.id));
        const flash = allFlashRaw().filter(d => visible.has(d.productId));
        const out = {
            ok: true, serverNow: nowFn(), flashSlotHours: FLASH_SLOT_HOURS,
            products, flashSales: flash.map(publicFlash), reviews: reviewsMap(),
            me: null, cart: [], orders: [], users: [], addresses: []
        };
        if (req.user) {
            out.me = publicUser(req.user);
            out.addresses = addressesFor(req.user.username);
            out.cart = cartFor(req.user.username);
            out.orders = ordersFor(req.user.role === 'admin' ? null : req.user.username);
            if (req.user.role === 'admin') {
                out.users = db.prepare('SELECT username, full_name AS fullName, email, phone, role FROM Users ORDER BY created_at').all();
            }
        } else if (req.sessionExpired) out.sessionExpired = true;
        res.json(out);
    });

    // ---------- Tài khoản ----------
    const getLock = key => {
        const r = db.prepare('SELECT * FROM LoginAttempts WHERE key = ?').get(key);
        const left = r && r.lock_until > nowFn() ? Math.ceil((r.lock_until - nowFn()) / 1000) : 0;
        return { secs: left, rec: r };
    };
    function recordFail(key) {
        const r = db.prepare('SELECT * FROM LoginAttempts WHERE key = ?').get(key) || { fails: 0, level: 0, lock_until: 0 };
        let fails = r.fails + 1, level = r.level, lockUntil = r.lock_until, locked = false;
        if (fails >= MAX_FAILS) { level++; fails = 0; lockUntil = nowFn() + Math.min(LOCK_BASE_S * 2 ** (level - 1), LOCK_MAX_S) * 1000; locked = true; }
        db.prepare('INSERT INTO LoginAttempts (key, fails, level, lock_until) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET fails=excluded.fails, level=excluded.level, lock_until=excluded.lock_until').run(key, fails, level, lockUntil);
        return { locked, remaining: MAX_FAILS - fails, secs: locked ? Math.ceil((lockUntil - nowFn()) / 1000) : 0 };
    }
    const clearFails = key => db.prepare('DELETE FROM LoginAttempts WHERE key = ?').run(key);

    api.post('/auth/register', async (req, res, next) => {
        try {
            await ready;
            if (!limit('regtry:' + req.ip, 40, 600000)) throw bad('Bạn thử quá nhiều lần. Vui lòng thử lại sau ít phút.', 429);
            const b = req.body || {};
            const fullName = cleanName(b.fullName);
            const email = cleanText(b.email, 100).toLowerCase();
            const phone = normPhone(b.phone);
            const password = String(b.password || '');
            const confirm = b.confirmPassword === undefined ? password : String(b.confirmPassword);
            if (!fullName || !email || !String(b.phone || '').trim() || !password) throw bad('Vui lòng nhập đầy đủ thông tin!');
            if (fullName.length < 2) throw bad('Họ và tên quá ngắn!');
            if (!validEmail(email)) throw bad('Email không hợp lệ');
            if (!validPhone(phone) || /[A-Za-z]/.test(String(b.phone))) throw bad(PHONE_ERR);
            const pwErr = passwordPolicyError(password, email.split('@')[0]);
            if (pwErr) throw bad(pwErr);
            if (password !== confirm) throw bad('Mật khẩu nhập lại không khớp!');
            if (userByLogin.get(email, email)) throw bad('Email này đã được đăng ký!', 409);
            if (db.prepare('SELECT 1 FROM Users WHERE phone = ?').get(phone)) throw bad('Số điện thoại này đã được dùng cho tài khoản khác!', 409);
            if (!limit('reg:' + req.ip, 5, 600000)) { logSec('rate_limit', '', 'Đăng ký quá nhiều lần', req.ip); throw bad('Bạn đăng ký quá nhiều tài khoản. Vui lòng thử lại sau ít phút.', 429); }
            const hash = await hashPassword(password);
            // tên đăng nhập nội bộ chính là email
            db.prepare('INSERT INTO Users (username, password_hash, full_name, phone, role, created_at, email) VALUES (?,?,?,?,?,?,?)').run(email, hash, fullName, phone, 'customer', nowFn(), email);
            logSec('register', email, 'Tạo tài khoản mới', req.ip);
            newSession(req, res, email);
            res.json({ ok: true, me: publicUser({ username: email, fullName, email, phone, role: 'customer' }) });
        } catch (e) { next(e); }
    });

    api.post('/auth/login', async (req, res, next) => {
        try {
            await ready;
            if (!limit('login:' + req.ip, 30, 60000)) throw bad('Bạn thử đăng nhập quá nhiều lần. Vui lòng chờ một lát.', 429);
            const username = cleanText((req.body || {}).username, 100).toLowerCase();
            const password = String((req.body || {}).password || '');
            if (!username || !password) throw bad('Vui lòng nhập email (hoặc tên đăng nhập) và mật khẩu.');
            const key = 'u:' + username;
            const lk = getLock(key);
            if (lk.secs > 0) {
                logSec('lock_block', username, 'Thử đăng nhập khi đang bị khóa', req.ip);
                return res.status(429).json({ ok: false, error: `Đăng nhập tạm thời bị khóa do nhập sai nhiều lần. Thử lại sau ${lk.secs} giây.`, lockSecs: lk.secs });
            }
            const u = userByLogin.get(username, username);
            const okPw = await verifyPassword(password, u ? u.password_hash : DUMMY_HASH);
            if (!u || !okPw) {
                const r = recordFail(key);
                logSec(r.locked ? 'lockout' : 'login_fail', username, r.locked ? `Sai ${MAX_FAILS} lần, tạm khóa` : 'Sai tên đăng nhập hoặc mật khẩu', req.ip);
                return res.status(401).json({ ok: false, error: r.locked ? `Bạn đã nhập sai ${MAX_FAILS} lần. Đăng nhập bị khóa tạm thời ${r.secs} giây.` : `Sai email/tên đăng nhập hoặc mật khẩu. Còn ${r.remaining} lần thử.`, lockSecs: r.secs });
            }
            clearFails(key);
            logSec('login_ok', u.username, 'Đăng nhập thành công', req.ip);
            newSession(req, res, u.username);
            res.json({ ok: true, me: rowToMe(u) });
        } catch (e) { next(e); }
    });

    api.post('/auth/logout', (req, res) => {
        if (req.sessionId) { db.prepare('DELETE FROM Sessions WHERE id = ?').run(req.sessionId); logSec('logout', req.user.username, 'Đăng xuất', req.ip); }
        res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
        res.json({ ok: true });
    });

    api.get('/auth/me', (req, res) => res.json({ ok: true, me: req.user ? publicUser(req.user) : null, expired: !!req.sessionExpired }));
    api.post('/auth/ping', needUser, (req, res) => res.json({ ok: true }));

    api.post('/auth/change-password', needUser, async (req, res, next) => {
        try {
            const oldP = String((req.body || {}).oldPassword || ''), newP = String((req.body || {}).newPassword || '');
            const key = 'pw:' + req.user.username;
            const lk = getLock(key);
            if (lk.secs > 0) throw bad(`Tạm khóa do nhập sai mật khẩu cũ nhiều lần. Thử lại sau ${lk.secs} giây.`, 429);
            const u = userByName.get(req.user.username);
            if (!(await verifyPassword(oldP, u.password_hash))) {
                recordFail(key); logSec('pw_fail', u.username, 'Sai mật khẩu cũ khi đổi mật khẩu', req.ip);
                throw bad('Mật khẩu hiện tại không đúng.');
            }
            clearFails(key);
            const err = passwordPolicyError(newP, u.username);
            if (err) throw bad(err);
            if (newP === oldP) throw bad('Mật khẩu mới phải khác mật khẩu cũ.');
            db.prepare('UPDATE Users SET password_hash = ? WHERE username = ?').run(await hashPassword(newP), u.username);
            db.prepare('DELETE FROM Sessions WHERE username = ? AND id <> ?').run(u.username, req.sessionId);   // đăng xuất các thiết bị khác
            logSec('pw_change', u.username, 'Đổi mật khẩu thành công', req.ip);
            res.json({ ok: true });
        } catch (e) { next(e); }
    });

    // ---------- Hồ sơ cá nhân ----------
    api.put('/account', needUser, (req, res, next) => {
        try {
            const b = req.body || {};
            const fullName = cleanName(b.fullName);
            const phone = normPhone(b.phone);
            const birthday = String(b.birthday || '').trim(), gender = String(b.gender || '').trim();
            if (!fullName || !String(b.phone || '').trim()) throw bad('Vui lòng nhập đầy đủ họ tên và số điện thoại!');
            if (fullName.length < 2) throw bad('Họ và tên quá ngắn!');
            if (!validPhone(phone) || /[A-Za-z]/.test(String(b.phone))) throw bad(PHONE_ERR);
            if (birthday && !validBirthday(birthday, clock.today())) throw bad('Ngày sinh không hợp lệ');
            if (gender && !GENDERS.includes(gender)) throw bad('Giới tính không hợp lệ');
            const dup = db.prepare('SELECT username FROM Users WHERE phone = ? AND username <> ?').get(phone, req.user.username);
            if (dup) throw bad('Số điện thoại này đã được dùng cho tài khoản khác!', 409);
            db.prepare('UPDATE Users SET full_name = ?, phone = ?, birthday = ?, gender = ? WHERE username = ?').run(fullName, phone, birthday || null, gender || null, req.user.username);
            logSec('profile', req.user.username, 'Cập nhật thông tin cá nhân', req.ip);
            res.json({ ok: true, me: publicUser({ ...req.user, fullName, phone, birthday, gender }) });
        } catch (e) { next(e); }
    });

    // Xóa tài khoản: cần nhập đúng mật khẩu. Đơn đang chờ xác nhận được hủy, đơn cũ giữ lại (đã ẩn danh) để đối soát doanh thu.
    api.post('/account/delete', needUser, async (req, res, next) => {
        try {
            if (req.user.role === 'admin') throw bad('Tài khoản quản trị không thể tự xóa.', 403);
            const key = 'pw:' + req.user.username;
            const lk = getLock(key);
            if (lk.secs > 0) throw bad(`Tạm khóa do nhập sai mật khẩu nhiều lần. Thử lại sau ${lk.secs} giây.`, 429);
            const u = userByName.get(req.user.username);
            if (!(await verifyPassword(String((req.body || {}).password || ''), u.password_hash))) {
                recordFail(key); logSec('pw_fail', u.username, 'Sai mật khẩu khi xóa tài khoản', req.ip);
                throw bad('Mật khẩu xác nhận không chính xác');
            }
            clearFails(key);
            const reason = cleanText((req.body || {}).reason, 120);
            db.transaction(() => {
                db.prepare("SELECT id FROM Orders WHERE username = ? AND status = 'Chờ xác nhận'").all(u.username).forEach(o => {
                    releaseFlash(o.id); restoreStock(o.id);
                    db.prepare("UPDATE Orders SET status = 'Đã hủy', cancel_reason = 'Khách đã xóa tài khoản' WHERE id = ?").run(o.id);
                });
                db.prepare("UPDATE Orders SET username = 'đã-xóa:' || username WHERE username = ?").run(u.username);
                db.prepare('DELETE FROM Users WHERE username = ?').run(u.username);   // kéo theo phiên, giỏ hàng, sổ địa chỉ
            })();
            logSec('account_delete', u.username, 'Xóa tài khoản' + (reason ? ': ' + reason : ''), req.ip);
            res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
            res.json({ ok: true });
        } catch (e) { next(e); }
    });

    // ---------- Sổ địa chỉ nhận hàng ----------
    function readAddress(b) {
        const recipient = cleanName(b.recipient), phone = normPhone(b.phone);
        const detail = cleanText(b.detail, 120), district = cleanText(b.district, 60), province = cleanText(b.province, 60);
        if (!detail) throw bad('Vui lòng nhập địa chỉ chi tiết');
        if (!recipient || !district || !province || !String(b.phone || '').trim()) throw bad('Vui lòng nhập đầy đủ thông tin địa chỉ!');
        if (recipient.length < 2) throw bad('Họ tên người nhận không hợp lệ!');
        if (!validPhone(phone) || /[A-Za-z]/.test(String(b.phone))) throw bad(PHONE_ERR);
        return { recipient, phone, detail, district, province, isDefault: !!b.isDefault };
    }
    const setDefaultAddr = (username, id) => { db.prepare('UPDATE Addresses SET is_default = 0 WHERE username = ?').run(username); db.prepare('UPDATE Addresses SET is_default = 1 WHERE id = ? AND username = ?').run(id, username); };
    api.get('/addresses', needUser, (req, res) => res.json({ ok: true, addresses: addressesFor(req.user.username) }));
    api.post('/addresses', needUser, (req, res, next) => {
        try {
            const a = readAddress(req.body || {});
            const n = db.prepare('SELECT COUNT(*) c FROM Addresses WHERE username = ?').get(req.user.username).c;
            if (n >= 10) throw bad('Bạn chỉ lưu được tối đa 10 địa chỉ.');
            db.transaction(() => {
                const id = Number(db.prepare('INSERT INTO Addresses (username, recipient, phone, detail, district, province, is_default) VALUES (?,?,?,?,?,?,0)').run(req.user.username, a.recipient, a.phone, a.detail, a.district, a.province).lastInsertRowid);
                if (a.isDefault || n === 0) setDefaultAddr(req.user.username, id);
            })();
            res.json({ ok: true, addresses: addressesFor(req.user.username) });
        } catch (e) { next(e); }
    });
    api.put('/addresses/:id', needUser, (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('SELECT 1 FROM Addresses WHERE id = ? AND username = ?').get(id, req.user.username)) throw bad('Không tìm thấy địa chỉ.', 404);
            const a = readAddress(req.body || {});
            db.transaction(() => {
                db.prepare('UPDATE Addresses SET recipient=?, phone=?, detail=?, district=?, province=? WHERE id=?').run(a.recipient, a.phone, a.detail, a.district, a.province, id);
                if (a.isDefault) setDefaultAddr(req.user.username, id);
            })();
            res.json({ ok: true, addresses: addressesFor(req.user.username) });
        } catch (e) { next(e); }
    });
    api.delete('/addresses/:id', needUser, (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            const cur = db.prepare('SELECT * FROM Addresses WHERE id = ? AND username = ?').get(id, req.user.username);
            if (!cur) throw bad('Không tìm thấy địa chỉ.', 404);
            db.transaction(() => {
                db.prepare('DELETE FROM Addresses WHERE id = ?').run(id);
                if (cur.is_default) { const nx = db.prepare('SELECT id FROM Addresses WHERE username = ? ORDER BY id LIMIT 1').get(req.user.username); if (nx) setDefaultAddr(req.user.username, nx.id); }
            })();
            res.json({ ok: true, addresses: addressesFor(req.user.username) });
        } catch (e) { next(e); }
    });

    // ---------- Giỏ hàng của từng tài khoản ----------
    function sanitizeCartItems(items) {
        if (!Array.isArray(items)) throw bad('Giỏ hàng không hợp lệ.');
        const map = new Map();
        items.slice(0, 100).forEach(i => {
            const id = parseInt(i && i.id, 10), qty = parseInt(i && i.qty, 10);
            if (!Number.isInteger(id) || !Number.isInteger(qty) || qty < 1) return;
            map.set(id, Math.min(99, (map.get(id) || 0) + qty));
        });
        const exists = db.prepare('SELECT 1 FROM Products WHERE id = ? AND active = 1');
        return [...map].filter(([id]) => exists.get(id)).map(([id, qty]) => ({ id, qty }));
    }
    const writeCart = db.transaction((username, items) => {
        db.prepare('DELETE FROM Carts WHERE username = ?').run(username);
        const ins = db.prepare('INSERT INTO Carts (username, product_id, qty) VALUES (?,?,?)');
        items.forEach(i => ins.run(username, i.id, i.qty));
    });
    api.put('/cart', needUser, (req, res, next) => {
        try {
            if (!limit('cart:' + req.user.username, 120, 60000)) throw bad('Bạn thao tác quá nhanh.', 429);
            const items = sanitizeCartItems((req.body || {}).items);
            const stockOf = db.prepare('SELECT name, stock FROM Products WHERE id = ?');
            const over = items.find(i => i.qty > stockOf.get(i.id).stock);
            if (over) throw bad(STOCK_ERR + ` (“${stockOf.get(over.id).name}” còn ${stockOf.get(over.id).stock}).`, 409);
            writeCart(req.user.username, items);
            res.json({ ok: true, cart: items });
        } catch (e) { next(e); }
    });
    api.post('/cart/merge', needUser, (req, res, next) => {   // gộp giỏ của khách vào giỏ tài khoản sau khi đăng nhập
        try {
            const guest = sanitizeCartItems((req.body || {}).items);
            const mine = cartFor(req.user.username);
            guest.forEach(g => { const ex = mine.find(i => i.id === g.id); if (ex) ex.qty = Math.min(99, ex.qty + g.qty); else mine.push(g); });
            const stockOf = db.prepare('SELECT stock FROM Products WHERE id = ? AND active = 1');
            const fit = mine.map(i => { const p = stockOf.get(i.id); return p ? { id: i.id, qty: Math.min(i.qty, p.stock) } : null; }).filter(i => i && i.qty > 0);
            mine.length = 0; fit.forEach(i => mine.push(i));
            writeCart(req.user.username, mine);
            res.json({ ok: true, cart: mine, merged: guest.reduce((s, g) => s + g.qty, 0) });
        } catch (e) { next(e); }
    });

    // ---------- Đặt hàng: server tự tính giá, Flash Sale, mã giảm giá ----------
    function couponResult(code, subtotal, username) {
        const c = COUPONS.find(x => x.code === String(code || '').trim().toUpperCase());
        if (!c) return { ok: false, msg: 'Mã giảm giá không tồn tại.' };
        if (c.expires && clock.vn().getTime() > Date.parse(c.expires + 'T23:59:59Z')) return { ok: false, msg: 'Mã đã hết hạn.' };
        if (subtotal < c.min) return { ok: false, msg: 'Đơn chưa đạt giá trị tối thiểu để dùng mã này.' };
        const mine = db.prepare("SELECT coupon FROM Orders WHERE username = ? AND status <> 'Đã hủy'").all(username);
        if (c.firstOrderOnly && mine.length > 0) return { ok: false, msg: 'Mã chỉ dành cho đơn hàng đầu tiên.' };
        if (mine.some(o => o.coupon === c.code)) return { ok: false, msg: 'Bạn đã dùng mã này rồi (mỗi tài khoản dùng 1 lần).' };
        let discount = c.type === 'percent' ? Math.round(subtotal * c.value / 100) : c.value;
        if (c.max) discount = Math.min(discount, c.max);
        return { ok: true, code: c.code, discount: Math.min(discount, subtotal) };
    }
    function newOrderId() {
        for (let i = 0; i < 20; i++) {
            const id = 'ĐH-' + (100000 + crypto.randomInt(900000));
            if (!db.prepare('SELECT 1 FROM Orders WHERE id = ?').get(id)) return id;
        }
        throw bad('Không tạo được mã đơn, vui lòng thử lại.', 500);
    }
    const createOrder = db.transaction((user, b) => {
        const items = sanitizeCartItems(b.items);
        if (!items.length) throw bad('Giỏ hàng đang trống!');
        const name = cleanName(b.name), phone = normPhone(b.phone), address = cleanText(b.address, 200);
        const payment = PAYMENTS.includes(b.payment) ? b.payment : PAYMENTS[0];
        if (!name || !phone || !address) throw bad('Vui lòng điền đầy đủ thông tin nhận hàng!');
        if (name.length < 2) throw bad('Họ tên không hợp lệ!');
        if (!validPhone(phone) || /[A-Za-z]/.test(String(b.phone))) throw bad(PHONE_ERR);

        const flash = allFlashRaw();
        const lines = [];
        for (const it of items) {
            const p = db.prepare('SELECT * FROM Products WHERE id = ?').get(it.id);
            const prod = rowToProduct(p);
            if (!prod.active) throw bad(`"${prod.name}" đã ngừng kinh doanh.`, 409);
            if (prod.stock < 1) throw bad(`"${prod.name}" đã hết hàng.`, 409);
            if (it.qty > prod.stock) throw bad(`${STOCK_ERR} ("${prod.name}" chỉ còn ${prod.stock}).`, 409);
            if (flashLock(prod, flash)) throw bad(`"${prod.name}" thuộc Flash Sale, chưa tới giờ mở bán!`, 409);
            const fl = liveFlash(prod, flash);
            if (fl && it.qty > remaining(fl)) throw bad(`"${prod.name}" chỉ còn ${remaining(fl)} suất Flash Sale. Vui lòng giảm số lượng.`, 409);
            lines.push({ pid: prod.id, name: prod.name, qty: it.qty, price: fl ? fl.flashPrice : prod.price, flash: fl });
        }
        const subtotal = lines.reduce((s, l) => s + l.price * l.qty, 0);
        let discount = 0, code = null;
        if (b.coupon) {
            const r = couponResult(b.coupon, subtotal, user.username);
            if (!r.ok) throw bad(r.msg);
            discount = r.discount; code = r.code;
        }
        const id = newOrderId();
        db.prepare(`INSERT INTO Orders (id, username, customer_name, phone, address, created_ms, date_str, payment, status, subtotal, discount, coupon, total, is_demo)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)`).run(id, user.username, name, phone, address, nowFn(), clock.orderDate(), payment, 'Chờ xác nhận', subtotal, discount, code, subtotal - discount);
        const insItem = db.prepare('INSERT INTO OrderItems (order_id, name, qty, price, flash_id, flash_day, product_id) VALUES (?,?,?,?,?,?,?)');
        lines.forEach(l => {
            insItem.run(id, l.name, l.qty, l.price, l.flash ? l.flash.id : null, l.flash ? clock.today() : null, l.pid);
            db.prepare('UPDATE Products SET stock = stock - ? WHERE id = ?').run(l.qty, l.pid);
            if (l.flash) db.prepare('UPDATE FlashSales SET sold = ?, sold_date = ? WHERE id = ?').run(soldNow(l.flash) + l.qty, clock.today(), l.flash.id);
        });
        db.prepare('DELETE FROM Carts WHERE username = ?').run(user.username);
        return id;
    });
    api.post('/orders', needUser, (req, res, next) => {
        try {
            if (!limit('order:' + req.user.username, 8, 60000)) throw bad('Bạn thao tác quá nhanh, vui lòng đợi một chút rồi đặt lại.', 429);
            const id = createOrder(req.user, req.body || {});
            const order = ordersFor(req.user.username).find(o => o.id === id);
            res.json({ ok: true, order, flashSales: allFlashRaw().map(publicFlash), products: allProducts().filter(p => p.active) });
        } catch (e) { next(e); }
    });
    api.post('/coupon/validate', needUser, (req, res) => {
        const subtotal = Math.max(0, parseInt((req.body || {}).subtotal, 10) || 0);
        res.json(couponResult((req.body || {}).code, subtotal, req.user.username));
    });

    // ---------- Thanh toán VNPay ----------
    const VNPAY_METHOD = 'Thẻ tín dụng / VNPAY';
    const vcfg = vnpay.config(options.env || process.env);
    const baseUrl = req => vcfg.publicUrl || (req.protocol + '://' + req.get('host'));
    api.get('/payment/config', (req, res) => res.json({ ok: true, vnpay: true, live: vcfg.live }));
    api.post('/orders/:id/vnpay', needUser, (req, res, next) => {
        try {
            if (!limit('pay:' + req.user.username, 10, 60000)) throw bad('Bạn thao tác quá nhanh, vui lòng đợi một chút.', 429);
            const o = ownOrder(req);
            if (o.username !== req.user.username) throw bad(NO_ORDER, 404);
            if (o.payment !== VNPAY_METHOD) throw bad('Đơn hàng này không chọn thanh toán VNPay.', 409);
            if (o.status !== 'Chờ xác nhận') throw bad('Đơn hàng đã được xử lý hoặc đã hủy, không thể thanh toán.', 409);
            if (o.pay_status === 'paid') throw bad('Đơn hàng đã được thanh toán.', 409);
            const b = baseUrl(req);
            const url = vnpay.buildPaymentUrl(vcfg, { orderId: o.id, amount: o.total, ip: req.ip, vnNow: clock.vn(), nowMs: nowFn(),
                returnUrl: b + '/api/payment/vnpay/return', mockUrl: b + '/pay/vnpay-mock' });
            res.json({ ok: true, url, live: vcfg.live });
        } catch (e) { next(e); }
    });
    // Xử lý kết quả (dùng chung cho Return URL và IPN). Trả về {code, order}
    function settleVnpay(q) {
        if (!q || !q.vnp_SecureHash || !vnpay.verify(q, vcfg.secret)) return { code: '97', msg: 'Chữ ký không hợp lệ' };
        const id = vnpay.orderIdFromRef(q.vnp_TxnRef);
        const o = id && db.prepare('SELECT * FROM Orders WHERE id = ?').get(id);
        if (!o) return { code: '01', msg: 'Không tìm thấy đơn hàng' };
        if (String(q.vnp_TmnCode) !== vcfg.tmn) return { code: '99', msg: 'Sai mã đơn vị' };
        if (parseInt(q.vnp_Amount, 10) !== o.total * 100) return { code: '04', msg: 'Số tiền không khớp', order: o };
        if (o.pay_status === 'paid') return { code: '02', msg: 'Đơn hàng đã được xác nhận trước đó', order: o, paid: true };
        const success = q.vnp_ResponseCode === '00' && q.vnp_TransactionStatus === '00';
        if (success && o.status === 'Chờ xác nhận') {
            db.prepare("UPDATE Orders SET pay_status = 'paid', pay_ref = ?, paid_at = ? WHERE id = ?").run(String(q.vnp_TransactionNo || q.vnp_TxnRef).slice(0, 40), clock.orderDate(), o.id);
            return { code: '00', msg: 'Thành công', order: o, paid: true };
        }
        if (!success) db.prepare("UPDATE Orders SET pay_status = 'failed' WHERE id = ? AND pay_status != 'paid'").run(o.id);
        return { code: '00', msg: 'Đã ghi nhận giao dịch không thành công', order: o, paid: false };
    }
    api.get('/payment/vnpay/return', (req, res) => {
        const r = settleVnpay(req.query);
        const id = r.order ? r.order.id : '';
        const state = r.code === '97' ? 'invalid' : (r.paid ? 'success' : 'failed');
        if (r.code === '97') logSec('denied', '', 'Return VNPay sai chữ ký', req.ip);
        res.redirect('/?pay=' + state + (id ? '#/don-hang/' + encodeURIComponent(id) : ''));
    });
    api.get('/payment/vnpay/ipn', (req, res) => {
        const r = settleVnpay(req.query);
        res.json({ RspCode: r.code, Message: r.msg });
    });
    // ---------- Cổng thanh toán giả lập (chỉ khi chưa cấu hình khóa VNPay thật): trang có mã QR như thật ----------
    const MOCK_CSS = `body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:linear-gradient(160deg,#e8f1fb,#f8fafc);margin:0;min-height:100vh;display:grid;place-items:center;color:#0f172a}
.c{background:#fff;border-radius:18px;box-shadow:0 12px 40px #0f172a1f;max-width:440px;width:calc(100% - 28px);overflow:hidden}.h{background:#005baa;color:#fff;padding:16px 22px;display:flex;justify-content:space-between;align-items:center}.h b{font-size:20px;letter-spacing:.5px}.h span{font-size:12px;opacity:.85}
.b{padding:22px}.r{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid #eef2f7;font-size:14px}.r b{font-weight:700}.qr{margin:18px auto 8px;width:230px;height:230px;border:2px solid #005baa;border-radius:14px;padding:8px;box-sizing:content-box}.qr svg{width:100%;height:100%;display:block}
.m{text-align:center;font-size:13px;color:#475569;margin:6px 0}.tm{text-align:center;font-weight:800;color:#e11d48;font-size:18px}.t{background:#fff7ed;border:1px dashed #fb923c;color:#9a3412;border-radius:8px;padding:8px 10px;font-size:12px;margin-top:14px}
.a{display:block;text-align:center;padding:12px;border-radius:10px;text-decoration:none;font-weight:700;margin-top:10px;font-size:14.5px}.ok{background:#16a34a;color:#fff}.no{background:#e2e8f0;color:#334155}.ln{background:#eff6ff;color:#005baa;border:1px solid #bfdbfe}
.big{font-size:54px;text-align:center;margin:6px 0}`;
    const page = (title, body, extraHead = '') => `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${MOCK_CSS}</style>${extraHead}</head><body><div class="c"><div class="h"><b>VNPAY<span style="font-weight:400;"> QR</span></b><span>Cổng thanh toán (giả lập)</span></div><div class="b">${body}</div></div></body></html>`;
    const money = a => (parseInt(a, 10) / 100).toLocaleString('vi-VN') + ' ₫';
    const mockReturnParams = (q, rc) => {
        const p = { vnp_TmnCode: q.vnp_TmnCode, vnp_Amount: q.vnp_Amount, vnp_TxnRef: q.vnp_TxnRef, vnp_OrderInfo: q.vnp_OrderInfo,
            vnp_ResponseCode: rc, vnp_TransactionNo: String(10000000 + crypto.randomInt(89999999)), vnp_TransactionStatus: rc === '00' ? '00' : '02', vnp_PayDate: q.vnp_CreateDate, vnp_BankCode: 'NCB' };
        return vnpay.sortedQuery(p) + '&vnp_SecureHash=' + vnpay.sign(p, vcfg.secret);
    };
    const mockGate = (req, res) => {
        if (vcfg.live) { res.status(404).send('Not found'); return null; }
        if (!vnpay.verify(req.query, vcfg.secret)) { res.status(400).send(page('Lỗi', '<p>Yêu cầu thanh toán không hợp lệ.</p>')); return null; }
        const id = vnpay.orderIdFromRef(req.query.vnp_TxnRef);
        const o = id && db.prepare('SELECT * FROM Orders WHERE id = ?').get(id);
        if (!o) { res.status(404).send(page('Lỗi', '<p>Không tìm thấy đơn hàng.</p>')); return null; }
        return o;
    };
    const rawQuery = req => req.originalUrl.slice(req.originalUrl.indexOf('?'));
    // Trang thanh toán trên máy tính: hiện mã QR (quét bằng điện thoại cùng Wi-Fi), tự cập nhật khi đã thanh toán
    app.get('/pay/vnpay-mock', (req, res) => {
        const o = mockGate(req, res); if (!o) return;
        const q = req.query, qs = rawQuery(req);
        let b = baseUrl(req);
        if (!vcfg.publicUrl && /^https?:\/\/(localhost|127\.0\.0\.1)/.test(b)) {   // điện thoại không vào được "localhost" -> dùng IP Wi-Fi của máy
            const ip = Object.values(os.networkInterfaces()).flat().find(i => i && i.family === 'IPv4' && !i.internal);
            if (ip) b = b.replace(/\/\/[^:/]+/, '//' + ip.address);
        }
        const scanUrl = b + '/pay/vnpay-mock/scan' + qs;
        const expire = Math.max(0, Math.floor((nowFn() - o.created_ms) / 1000));
        require('qrcode').toString(scanUrl, { type: 'svg', margin: 0, errorCorrectionLevel: 'M' }, (err, svg) => {
            if (err) return res.status(500).send('QR error');
            res.type('html').send(page('Thanh toán VNPay QR', `
<div class="r"><span>Đơn hàng</span><b>${o.id}</b></div><div class="r"><span>Nhà cung cấp</span><b>TechNova</b></div><div class="r"><span>Số tiền</span><b style="color:#005baa;font-size:18px;">${money(q.vnp_Amount)}</b></div>
<div class="qr" id="qr">${svg}</div><div class="m">Mở ứng dụng ngân hàng / VNPAY, chọn <b>Quét mã QR</b> để thanh toán</div><div class="tm" id="tm">15:00</div><div class="m">Mã sẽ hết hạn sau thời gian trên</div>
<div id="st" class="m" style="color:#475569;">⏳ Đang chờ thanh toán...</div>
<a class="a ln" href="/pay/vnpay-mock/scan${qs}">📱 Giả lập quét mã bằng điện thoại (demo)</a>
<div class="t">Đây là trang mô phỏng để demo, không trừ tiền thật. Đặt VNPAY_TMN_CODE và VNPAY_HASH_SECRET để dùng VNPay sandbox thật.</div>
<script>
var left=900-${Math.min(expire, 899)},poll;function f(n){return(n<10?'0':'')+n}
function tick(){if(left<=0){document.getElementById('tm').textContent='00:00';document.getElementById('st').textContent='⌛ Mã QR đã hết hạn, hãy quay lại cửa hàng và bấm "Thanh toán ngay".';document.getElementById('qr').style.opacity='.2';clearInterval(poll);return}
document.getElementById('tm').textContent=f(Math.floor(left/60))+':'+f(left%60);left--;setTimeout(tick,1000)}tick();
poll=setInterval(function(){fetch('/pay/vnpay-mock/status${qs}').then(function(r){return r.json()}).then(function(j){if(j.paid){clearInterval(poll);location.replace('/pay/vnpay-mock/done?state=success&id='+encodeURIComponent(j.id))}}).catch(function(){})},2000);
</script>`));
        });
    });
    app.get('/pay/vnpay-mock/status', (req, res) => {
        const o = mockGate(req, res); if (!o) return;
        res.json({ paid: o.pay_status === 'paid', id: o.id });
    });
    // Trang "điện thoại quét QR": xác nhận hoặc hủy giao dịch
    app.get('/pay/vnpay-mock/scan', (req, res) => {
        const o = mockGate(req, res); if (!o) return;
        const q = req.query;
        res.type('html').send(page('Xác nhận thanh toán', `
<div class="r"><span>Đơn hàng</span><b>${o.id}</b></div><div class="r"><span>Số tiền</span><b style="color:#005baa;font-size:18px;">${money(q.vnp_Amount)}</b></div><div class="r"><span>Nguồn tiền</span><b>Ngân hàng NCB ••••1432</b></div>
<a class="a ok" href="/pay/vnpay-mock/result?${mockReturnParams(q, '00')}">Xác nhận thanh toán</a><a class="a no" href="/pay/vnpay-mock/result?${mockReturnParams(q, '24')}">Hủy giao dịch</a>`));
    });
    app.get('/pay/vnpay-mock/result', (req, res) => {
        if (vcfg.live) return res.status(404).send('Not found');
        const r = settleVnpay(req.query);
        const ok = !!r.paid, id = r.order ? r.order.id : '';
        res.redirect('/pay/vnpay-mock/done?state=' + (ok ? 'success' : 'failed') + '&id=' + encodeURIComponent(id));
    });
    app.get('/pay/vnpay-mock/done', (req, res) => {
        const ok = req.query.state === 'success', id = String(req.query.id || '').replace(/[^0-9ĐH-]/g, '');
        res.type('html').send(page(ok ? 'Thanh toán thành công' : 'Thanh toán chưa thành công', `
<div class="big">${ok ? '✅' : '⚠️'}</div><h2 style="text-align:center;margin:4px 0 6px;">${ok ? 'Thanh toán thành công' : 'Thanh toán chưa thành công'}</h2>
<div class="m">${ok ? 'Đơn hàng ' + id + ' đã được thanh toán. Bạn có thể đóng tab này và quay lại TechNova.' : 'Giao dịch đã bị hủy hoặc thất bại. Bạn có thể thanh toán lại trong chi tiết đơn hàng.'}</div>
<a class="a ln" href="/#/don-hang/${encodeURIComponent(id)}">Về TechNova</a>`));
    });

    const cancelTx = db.transaction((id, reason) => {
        releaseFlash(id); restoreStock(id);
        db.prepare("UPDATE Orders SET status = 'Đã hủy', cancel_reason = ? WHERE id = ?").run(reason, id);
    });
    const NO_ORDER = 'Đơn hàng không tồn tại hoặc bạn không có quyền truy cập';
    function ownOrder(req) {   // chủ đơn hoặc admin; không phân biệt "không tồn tại" và "không phải của bạn"
        const o = db.prepare('SELECT * FROM Orders WHERE id = ?').get(String(req.params.id));
        if (!o || (o.username !== req.user.username && req.user.role !== 'admin')) {
            if (o) logSec('denied', req.user.username, 'Truy cập đơn không thuộc về mình: ' + o.id, req.ip);
            throw bad(NO_ORDER, 404);
        }
        return o;
    }
    api.get('/orders/:id', needUser, (req, res, next) => {
        try { const o = ownOrder(req); res.json({ ok: true, order: ordersFor(null).find(x => x.id === o.id) }); } catch (e) { next(e); }
    });
    api.post('/orders/:id/cancel', needUser, (req, res, next) => {
        try {
            const o = ownOrder(req);
            if (o.status !== 'Chờ xác nhận') throw bad('Không thể hủy đơn hàng đã được xử lý', 409);
            const r = cleanText((req.body || {}).reason, 100);
            const reason = r || CANCEL_REASONS[0];
            cancelTx(o.id, reason);
            logSec('order_cancel', req.user.username, 'Hủy đơn ' + o.id, req.ip);
            res.json({ ok: true, flashSales: allFlashRaw().map(publicFlash), products: allProducts().filter(p => p.active) });
        } catch (e) { next(e); }
    });
    api.put('/orders/:id/shipping', needUser, (req, res, next) => {
        try {
            const o = ownOrder(req);
            if (o.username !== req.user.username) throw bad(NO_ORDER, 404);
            if (o.status !== 'Chờ xác nhận') throw bad('Không thể thay đổi thông tin khi đơn hàng đã được xử lý', 409);
            const b = req.body || {};
            const name = cleanName(b.name), phone = normPhone(b.phone), address = cleanText(b.address, 200);
            if (!name || !address || !String(b.phone || '').trim()) throw bad('Vui lòng điền đầy đủ thông tin nhận hàng!');
            if (name.length < 2) throw bad('Họ tên không hợp lệ!');
            if (!validPhone(phone) || /[A-Za-z]/.test(String(b.phone))) throw bad(PHONE_ERR);
            db.prepare('UPDATE Orders SET customer_name = ?, phone = ?, address = ? WHERE id = ?').run(name, phone, address, o.id);
            logSec('order_edit', req.user.username, 'Sửa thông tin nhận hàng đơn ' + o.id, req.ip);
            res.json({ ok: true, order: ordersFor(req.user.username).find(x => x.id === o.id) });
        } catch (e) { next(e); }
    });

    // ---------- Đánh giá sản phẩm ----------
    api.post('/reviews', (req, res, next) => {
        try {
            if (!limit('review:' + req.ip, 8, 60000)) throw bad('Bạn gửi đánh giá quá nhanh, vui lòng đợi một chút.', 429);
            const b = req.body || {};
            const productId = parseInt(b.productId, 10);
            const prod = db.prepare('SELECT * FROM Products WHERE id = ?').get(productId);
            if (!prod) throw bad('Sản phẩm không tồn tại.', 404);
            const name = cleanName(b.name) || 'Khách hàng ẩn danh';
            const rating = Math.min(5, Math.max(1, parseInt(b.rating, 10) || 5));
            const comment = cleanText(b.comment, 500);
            if (comment.length < 5) throw bad('Vui lòng nhập nội dung nhận xét (ít nhất 5 ký tự)!');
            if (db.prepare('SELECT 1 FROM Reviews WHERE product_id = ? AND user_name = ? AND comment = ?').get(productId, name, comment)) throw bad('Bạn đã gửi nhận xét này rồi!', 409);
            const verified = req.user ? !!db.prepare(`SELECT 1 FROM Orders o JOIN OrderItems i ON i.order_id = o.id
                WHERE o.username = ? AND o.status <> 'Đã hủy' AND i.name = ? LIMIT 1`).get(req.user.username, prod.name) : false;
            const ts = nowFn();
            const id = 'u' + ts.toString(36) + crypto.randomBytes(3).toString('hex');
            db.prepare('INSERT INTO Reviews (id, product_id, username, user_name, rating, comment, ts, verified) VALUES (?,?,?,?,?,?,?,?)').run(id, productId, req.user ? req.user.username : null, name, rating, comment, ts, verified ? 1 : 0);
            res.json({ ok: true, review: { id, user: name, rating, ts, comment, verified, helpful: 0, reply: null } });
        } catch (e) { next(e); }
    });

    // ======================= API quản trị (chỉ admin) =======================
    const admin = express.Router();
    api.use('/admin', needAdmin, admin);

    const CATEGORIES = new Set(seedProducts().map(p => p.category));
    function imageUrlOk(u) {
        if (/^\/uploads\/[a-f0-9]{16}\.(jpg|png|gif|webp)$/.test(u)) return true;
        if (!/^https?:\/\//i.test(u)) return false;
        let ext = '';
        try { const m = /\.([a-z0-9]+)$/i.exec(new URL(u).pathname); ext = m ? m[1].toLowerCase() : ''; } catch (e) { return false; }
        return ext === '' || IMG_EXT.includes(ext);       // có đuôi thì phải là đuôi ảnh (.exe, .txt... bị từ chối)
    }
    function readProduct(b, existing) {
        const name = cleanText(b.name, 120), category = cleanText(b.category, 40);
        const priceRaw = b.price === '' || b.price == null ? NaN : Number(b.price);
        const specs = cleanText(b.specs, 300), desc = cleanText(b.description, 600);
        const image = String(b.image || '').trim().slice(0, 500) || (existing && existing.image) || 'https://placehold.co/600x450?text=TechNova';
        if (!name || Number.isNaN(priceRaw)) throw bad('Vui lòng nhập đầy đủ các trường bắt buộc (Tên sản phẩm, Giá bán)!');
        const price = Math.floor(priceRaw);
        if (!(price > 0) || price > 2000000000) throw bad('Giá bán không hợp lệ');
        if (!CATEGORIES.has(category)) throw bad('Danh mục không hợp lệ!');
        if (!imageUrlOk(image)) throw bad(IMG_ERR);
        let stock;
        if (b.stock === undefined || b.stock === '' || b.stock === null) stock = existing ? existing.stock : 10;
        else { stock = Number(b.stock); if (!Number.isInteger(stock) || stock < 0 || stock > 1000000) throw bad('Số lượng tồn kho không hợp lệ'); }
        const active = b.active === undefined ? (existing ? existing.active : 1) : (b.active ? 1 : 0);
        let oldPrice = b.oldPrice === '' || b.oldPrice == null ? Math.round(price * 1.12) : Math.floor(Number(b.oldPrice));
        if (!(oldPrice > price)) throw bad('Giá gốc niêm yết phải lớn hơn giá bán (hoặc để trống để tự tính).');
        return { name, category, price, oldPrice, discount: '-' + Math.round((1 - price / oldPrice) * 100) + '%', specs, image, stock, active, description: desc || (existing ? existing.description : 'Đang cập nhật mô tả sản phẩm.') };
    }
    admin.post('/products', (req, res, next) => {
        try {
            const p = readProduct(req.body || {}, null);
            const id = db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM Products').get().n;
            insertProduct(db, { id, ...p });
            adminLog(req, 'Thêm sản phẩm #' + id);
            res.json({ ok: true, product: { id, ...p } });
        } catch (e) { next(e); }
    });
    admin.put('/products/:id', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            const cur = db.prepare('SELECT * FROM Products WHERE id = ?').get(id);
            if (!cur) throw bad('Không tìm thấy sản phẩm.', 404);
            const p = readProduct(req.body || {}, rowToProduct(cur));
            db.prepare('UPDATE Products SET name=@name, category=@category, price=@price, old_price=@oldPrice, discount=@discount, specs=@specs, image=@image, description=@description, stock=@stock, active=@active WHERE id=@id').run({ ...p, id });
            adminLog(req, 'Sửa sản phẩm #' + id);
            res.json({ ok: true, product: { id, ...p } });
        } catch (e) { next(e); }
    });
    admin.patch('/products/:id/stock', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('SELECT 1 FROM Products WHERE id = ?').get(id)) throw bad('Không tìm thấy sản phẩm.', 404);
            const raw = (req.body || {}).stock, stock = Number(raw);
            if (raw === '' || raw == null || !Number.isInteger(stock) || stock < 0 || stock > 1000000) throw bad('Số lượng tồn kho không hợp lệ');
            db.prepare('UPDATE Products SET stock = ? WHERE id = ?').run(stock, id);
            adminLog(req, `Tồn kho SP${id} = ${stock}`);
            res.json({ ok: true, product: rowToProduct(db.prepare('SELECT * FROM Products WHERE id = ?').get(id)) });
        } catch (e) { next(e); }
    });
    admin.patch('/products/:id/status', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('SELECT 1 FROM Products WHERE id = ?').get(id)) throw bad('Không tìm thấy sản phẩm.', 404);
            const active = (req.body || {}).active ? 1 : 0;
            db.prepare('UPDATE Products SET active = ? WHERE id = ?').run(active, id);
            adminLog(req, `SP${id} → ${active ? 'đang kinh doanh' : 'ngừng kinh doanh'}`);
            res.json({ ok: true, product: rowToProduct(db.prepare('SELECT * FROM Products WHERE id = ?').get(id)) });
        } catch (e) { next(e); }
    });
    // Tải ảnh lên: chỉ nhận JPG/PNG/GIF/WEBP (kiểm tra bằng nội dung thật của tệp, không tin tên tệp), tối đa 2MB
    admin.post('/upload', express.json({ limit: '3mb' }), (req, res, next) => {
        try {
            const m = /^data:image\/[a-z+.-]+;base64,([A-Za-z0-9+/=\s]+)$/.exec(String((req.body || {}).data || ''));
            if (!m) throw bad(IMG_ERR);
            const buf = Buffer.from(m[1], 'base64');
            if (buf.length < 12 || buf.length > 2 * 1024 * 1024) throw bad('Ảnh phải nhỏ hơn 2MB.');
            let ext = '';
            if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) ext = 'jpg';
            else if (buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) ext = 'png';
            else if (buf.slice(0, 4).toString('latin1') === 'GIF8') ext = 'gif';
            else if (buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') ext = 'webp';
            if (!ext) throw bad(IMG_ERR);
            fs.mkdirSync(uploadDir, { recursive: true });
            const name = crypto.randomBytes(8).toString('hex') + '.' + ext;
            fs.writeFileSync(path.join(uploadDir, name), buf);
            adminLog(req, 'Tải ảnh lên ' + name);
            res.json({ ok: true, url: '/uploads/' + name });
        } catch (e) { next(e); }
    });
    admin.delete('/products/:id', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('DELETE FROM Products WHERE id = ?').run(id).changes) throw bad('Không tìm thấy sản phẩm.', 404);
            adminLog(req, 'Xóa sản phẩm #' + id);
            res.json({ ok: true });
        } catch (e) { next(e); }
    });
    admin.post('/products-reset', (req, res) => {
        db.transaction(() => {
            const have = new Set(db.prepare('SELECT id FROM Products').all().map(r => r.id));
            seedProducts().forEach(p => { if (have.has(p.id)) db.prepare('UPDATE Products SET name=@name, category=@category, price=@price, old_price=@oldPrice, discount=@discount, specs=@specs, image=@image, description=@description WHERE id=@id').run(p); else insertProduct(db, p); });
            // xóa sản phẩm do admin thêm ngoài danh sách gốc
            const seedIds = new Set(seedProducts().map(p => p.id));
            db.prepare('SELECT id FROM Products').all().forEach(r => { if (!seedIds.has(r.id)) db.prepare('DELETE FROM Products WHERE id = ?').run(r.id); });
            if (db.prepare('SELECT COUNT(*) c FROM FlashSales').get().c === 0) seedFlashSales(db, clock);
        })();
        adminLog(req, 'Khôi phục sản phẩm gốc');
        res.json({ ok: true, products: allProducts(), flashSales: allFlashRaw().map(publicFlash) });
    });

    function readFlash(b, ignoreId) {
        const productId = parseInt(b.productId, 10), slot = parseInt(b.slot, 10);
        const flashPrice = Math.floor(Number(b.flashPrice)), qty = Math.floor(Number(b.qty));
        const prod = db.prepare('SELECT * FROM Products WHERE id = ?').get(productId);
        if (!prod) throw bad('Vui lòng chọn sản phẩm!');
        if (!(slot >= 0 && slot <= 3)) throw bad('Khung giờ không hợp lệ!');
        if (!(flashPrice > 0)) throw bad('Giá Flash Sale phải lớn hơn 0!');
        if (flashPrice >= prod.price) throw bad('Giá Flash Sale phải thấp hơn giá bán hiện tại!');
        if (!(qty >= 1 && qty <= 100000)) throw bad('Số suất phải từ 1 trở lên!');
        const dup = db.prepare('SELECT id FROM FlashSales WHERE product_id = ? AND slot = ?').get(productId, slot);
        if (dup && dup.id !== ignoreId) throw bad('Sản phẩm này đã có suất Flash Sale trong khung giờ đó!', 409);
        return { productId, slot, flashPrice, qty };
    }
    admin.post('/flash', (req, res, next) => {
        try {
            const f = readFlash(req.body || {}, null);
            const info = db.prepare('INSERT INTO FlashSales (product_id, slot, flash_price, qty, sold, sold_date) VALUES (?,?,?,?,0,?)').run(f.productId, f.slot, f.flashPrice, f.qty, clock.today());
            adminLog(req, 'Thêm Flash Sale #' + info.lastInsertRowid);
            res.json({ ok: true, flashSales: allFlashRaw().map(publicFlash), id: Number(info.lastInsertRowid) });
        } catch (e) { next(e); }
    });
    admin.put('/flash/:id', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('SELECT 1 FROM FlashSales WHERE id = ?').get(id)) throw bad('Không tìm thấy suất Flash Sale.', 404);
            const f = readFlash(req.body || {}, id);
            db.prepare('UPDATE FlashSales SET product_id=?, slot=?, flash_price=?, qty=? WHERE id=?').run(f.productId, f.slot, f.flashPrice, f.qty, id);
            adminLog(req, 'Sửa Flash Sale #' + id);
            res.json({ ok: true, flashSales: allFlashRaw().map(publicFlash) });
        } catch (e) { next(e); }
    });
    admin.delete('/flash/:id', (req, res, next) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (!db.prepare('DELETE FROM FlashSales WHERE id = ?').run(id).changes) throw bad('Không tìm thấy suất Flash Sale.', 404);
            adminLog(req, 'Xóa Flash Sale #' + id);
            res.json({ ok: true, flashSales: allFlashRaw().map(publicFlash) });
        } catch (e) { next(e); }
    });

    admin.patch('/orders/:id/status', (req, res, next) => {
        try {
            const status = String((req.body || {}).status || '');
            if (!ORDER_STATUSES.includes(status)) throw bad('Trạng thái không hợp lệ.');
            const o = db.prepare('SELECT * FROM Orders WHERE id = ?').get(String(req.params.id));
            if (!o) throw bad('Không tìm thấy đơn hàng.', 404);
            if (o.status === 'Đã giao thành công' || o.status === 'Đã hủy') throw bad('Không thể thay đổi trạng thái đối với đơn hàng đã hoàn tất hoặc bị hủy', 409);
            if (status === o.status) throw bad('Đơn hàng đang ở trạng thái này rồi.', 409);
            if (ORDER_RANK[status] < ORDER_RANK[o.status]) throw bad('Không thể chuyển đơn hàng về trạng thái trước đó.', 409);
            db.transaction(() => {
                if (status === 'Đã hủy') { releaseFlash(o.id); restoreStock(o.id); db.prepare("UPDATE Orders SET cancel_reason = 'Cửa hàng hủy đơn' WHERE id = ?").run(o.id); }
                db.prepare('UPDATE Orders SET status = ? WHERE id = ?').run(status, o.id);
            })();
            adminLog(req, `Đơn ${o.id} → ${status}`);
            res.json({ ok: true, flashSales: allFlashRaw().map(publicFlash), products: allProducts() });
        } catch (e) { next(e); }
    });

    admin.post('/demo-orders', (req, res, next) => {
        try {
            const list = Array.isArray((req.body || {}).orders) ? req.body.orders.slice(0, 60) : [];
            if (!list.length) throw bad('Không có đơn mẫu.');
            const ins = db.prepare(`INSERT OR IGNORE INTO Orders (id, username, customer_name, phone, address, created_ms, date_str, payment, status, subtotal, discount, coupon, total, is_demo)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)`);
            const insItem = db.prepare('INSERT INTO OrderItems (order_id, name, qty, price) VALUES (?,?,?,?)');
            let made = 0;
            db.transaction(() => {
                list.forEach(o => {
                    if (!/^ĐH-D\d{6}$/.test(String(o.id))) return;
                    const status = ORDER_STATUSES.includes(o.status) ? o.status : 'Chờ xác nhận';
                    const num = v => Math.max(0, Math.min(2e9, Math.floor(Number(v) || 0)));
                    const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2})$/.exec(String(o.date || ''));
                    const when = m ? Date.UTC(+m[3], +m[2] - 1, +m[1], +m[4] - 7, +m[5]) : nowFn();
                    const r = ins.run(String(o.id), 'demo', cleanName(o.customerName) || 'Khách mẫu', normPhone(o.phone).slice(0, 11), cleanText(o.address, 120), when, cleanText(o.date, 20),
                        PAYMENTS.includes(o.payment) ? o.payment : PAYMENTS[0], status, num(o.subtotal), num(o.discount), o.coupon ? cleanText(o.coupon, 20) : null, num(o.total));
                    if (r.changes) { made++; (Array.isArray(o.items) ? o.items.slice(0, 10) : []).forEach(i => insItem.run(String(o.id), cleanText(i.name, 120), Math.max(1, Math.min(99, parseInt(i.qty, 10) || 1)), num(i.price))); }
                });
            })();
            adminLog(req, `Thêm ${made} đơn mẫu`);
            res.json({ ok: true, made, orders: ordersFor(null) });
        } catch (e) { next(e); }
    });
    admin.delete('/demo-orders', (req, res) => {
        db.prepare('DELETE FROM Orders WHERE is_demo = 1').run();
        adminLog(req, 'Xóa đơn mẫu');
        res.json({ ok: true, orders: ordersFor(null) });
    });

    admin.get('/carts', (req, res) => {
        const flash = allFlashRaw();
        const prods = new Map(allProducts().map(p => [p.id, p]));
        const users = db.prepare('SELECT username, full_name AS fullName, role FROM Users ORDER BY created_at').all();
        const entries = users.map(u => ({
            username: u.username, fullName: u.fullName, role: u.role,
            items: cartFor(u.username).filter(i => prods.has(i.id)).map(i => {
                const p = prods.get(i.id), fl = liveFlash(p, flash);
                return { id: i.id, name: p.name, qty: i.qty, unit: fl ? fl.flashPrice : p.price };
            })
        }));
        res.json({ ok: true, entries });
    });
    admin.get('/security-log', (req, res) => {
        const rows = db.prepare('SELECT ts AS t, type, username AS user, detail FROM SecurityLog ORDER BY id DESC LIMIT 200').all();
        res.json({ ok: true, log: rows });
    });
    admin.delete('/security-log', (req, res) => {
        db.prepare('DELETE FROM SecurityLog').run();
        logSec('admin', req.user.username, 'Đã xóa nhật ký bảo mật', req.ip);
        res.json({ ok: true });
    });

    api.use((req, res) => res.status(404).json({ ok: false, error: 'Không tìm thấy API.' }));

    // ======================= Giao diện (frontend) =======================
    app.get('/healthz', (req, res) => res.json({ ok: true }));
    app.use('/uploads', express.static(uploadDir, { index: false, setHeaders: res => { res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox"); res.setHeader('X-Content-Type-Options', 'nosniff'); } }));
    app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', setHeaders: (res, p) => { if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache'); } }));

    // ======================= Xử lý lỗi =======================
    app.use((err, req, res, next) => {
        if (res.headersSent) return next(err);
        if (err instanceof HttpError) return res.status(err.status).json({ ok: false, error: err.message });
        if (err && err.type === 'entity.parse.failed') return res.status(400).json({ ok: false, error: 'Dữ liệu gửi lên không hợp lệ.' });
        if (err && err.type === 'entity.too.large') return res.status(413).json({ ok: false, error: 'Dữ liệu quá lớn.' });
        console.error('[lỗi]', err);
        res.status(500).json({ ok: false, error: 'Lỗi máy chủ, vui lòng thử lại.' });
    });

    // dọn phiên hết hạn mỗi 10 phút
    const sweeper = setInterval(() => { db.prepare('DELETE FROM Sessions WHERE last_active < ?').run(nowFn() - SESSION_MAX_MS); }, 600000);
    sweeper.unref();

    return { app, db, ready, clock };
}

module.exports = { createApp };

// ======================= Chạy trực tiếp =======================
if (require.main === module) {
    const PORT = parseInt(process.env.PORT, 10) || 3000;
    const HOST = process.env.HOST || '0.0.0.0';
    const { app, ready } = createApp({
        dbFile: process.env.DB_FILE,
        adminPassword: process.env.ADMIN_PASSWORD,
        trustProxy: !!process.env.TRUST_PROXY,
        cookieSecure: process.env.COOKIE_SECURE === '1'
    });
    ready.then(() => {
        app.listen(PORT, HOST, () => {
            console.log('\n  TechNova đang chạy!');
            console.log(`  Máy tính này : http://localhost:${PORT}`);
            Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal).forEach(i => console.log(`  Điện thoại   : http://${i.address}:${PORT}   (cùng Wi-Fi)`));
            console.log('  Tài khoản mẫu: admin / ' + (process.env.ADMIN_PASSWORD || '123') + '   |   khach / 123');
            if (!process.env.ADMIN_PASSWORD) console.log('  ⚠ Đang dùng mật khẩu admin mặc định. Đặt biến ADMIN_PASSWORD trước khi mở cho người khác truy cập.');
            console.log('');
        });
    }).catch(e => { console.error(e); process.exit(1); });
}
