'use strict';
/**
 * db.js - Cơ sở dữ liệu SQLite thật (file data/technova.db)
 * Các bảng: Users, Sessions, Products, FlashSales, Orders, OrderItems, Carts, Reviews,
 *           SecurityLog, LoginAttempts
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

// ---------- Thời gian theo giờ Việt Nam (UTC+7), không phụ thuộc múi giờ máy chủ ----------
const VN_OFFSET_MS = 7 * 3600 * 1000;
const FLASH_SLOT_HOURS = 6;
const pad2 = n => String(n).padStart(2, '0');
function makeClock(nowFn) {
    const vn = () => new Date(nowFn() + VN_OFFSET_MS);          // đọc bằng getUTC*()
    return {
        now: nowFn,
        vn,
        slot: () => Math.floor(vn().getUTCHours() / FLASH_SLOT_HOURS),
        today: () => { const d = vn(); return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`; },
        orderDate: () => { const d = vn(); return `${d.getUTCDate()}/${d.getUTCMonth() + 1}/${d.getUTCFullYear()} ${d.getUTCHours()}:${pad2(d.getUTCMinutes())}`; }
    };
}

// ---------- Mật khẩu: scrypt + salt ngẫu nhiên ----------
async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const key = await scrypt(password, salt, 64);
    return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
async function verifyPassword(password, stored) {
    const parts = String(stored || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    const key = await scrypt(String(password), salt, expected.length);
    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
// Băm giả để thời gian phản hồi không lộ tên đăng nhập có tồn tại hay không
const DUMMY_HASH = 'scrypt$' + '00'.repeat(16) + '$' + '00'.repeat(64);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS Users (
    username      TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL,
    phone         TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','admin')),
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS Sessions (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL REFERENCES Users(username) ON DELETE CASCADE ON UPDATE CASCADE,
    created_at  INTEGER NOT NULL,
    last_active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS Products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    price       INTEGER NOT NULL CHECK (price > 0),
    old_price   INTEGER NOT NULL,
    discount    TEXT NOT NULL,
    specs       TEXT NOT NULL,
    image       TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS FlashSales (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id  INTEGER NOT NULL REFERENCES Products(id) ON DELETE CASCADE,
    slot        INTEGER NOT NULL CHECK (slot BETWEEN 0 AND 3),
    flash_price INTEGER NOT NULL CHECK (flash_price > 0),
    qty         INTEGER NOT NULL CHECK (qty > 0),
    sold        INTEGER NOT NULL DEFAULT 0,
    sold_date   TEXT NOT NULL,
    UNIQUE (product_id, slot)
);
CREATE TABLE IF NOT EXISTS Orders (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    phone         TEXT NOT NULL,
    address       TEXT NOT NULL,
    created_ms    INTEGER NOT NULL,
    date_str      TEXT NOT NULL,
    payment       TEXT NOT NULL,
    status        TEXT NOT NULL,
    subtotal      INTEGER NOT NULL,
    discount      INTEGER NOT NULL DEFAULT 0,
    coupon        TEXT,
    total         INTEGER NOT NULL,
    is_demo       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON Orders(username);
CREATE TABLE IF NOT EXISTS OrderItems (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id   TEXT NOT NULL REFERENCES Orders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    qty        INTEGER NOT NULL,
    price      INTEGER NOT NULL,
    flash_id   INTEGER,
    flash_day  TEXT
);
CREATE TABLE IF NOT EXISTS Carts (
    username   TEXT NOT NULL REFERENCES Users(username) ON DELETE CASCADE ON UPDATE CASCADE,
    product_id INTEGER NOT NULL REFERENCES Products(id) ON DELETE CASCADE,
    qty        INTEGER NOT NULL CHECK (qty > 0),
    PRIMARY KEY (username, product_id)
);
CREATE TABLE IF NOT EXISTS Reviews (
    id         TEXT PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES Products(id) ON DELETE CASCADE,
    username   TEXT,
    user_name  TEXT NOT NULL,
    rating     INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment    TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    verified   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reviews_prod ON Reviews(product_id);
CREATE TABLE IF NOT EXISTS SecurityLog (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    type     TEXT NOT NULL,
    username TEXT,
    detail   TEXT,
    ip       TEXT
);
CREATE TABLE IF NOT EXISTS LoginAttempts (
    key        TEXT PRIMARY KEY,
    fails      INTEGER NOT NULL DEFAULT 0,
    level      INTEGER NOT NULL DEFAULT 0,
    lock_until INTEGER NOT NULL DEFAULT 0
);
`;

// Bổ sung cột/bảng mới cho cơ sở dữ liệu đã tạo từ phiên bản cũ (chạy an toàn nhiều lần)
function migrate(db) {
    const cols = t => db.prepare(`PRAGMA table_info(${t})`).all().map(c => c.name);
    const add = (t, c, def) => { if (!cols(t).includes(c)) db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`); };
    add('Users', 'email', 'TEXT');
    add('Users', 'birthday', 'TEXT');
    add('Users', 'gender', 'TEXT');
    add('Products', 'stock', 'INTEGER NOT NULL DEFAULT 50');
    add('Products', 'active', 'INTEGER NOT NULL DEFAULT 1');
    add('Orders', 'cancel_reason', 'TEXT');
    add('OrderItems', 'product_id', 'INTEGER');
    add('Orders', 'pay_status', "TEXT NOT NULL DEFAULT 'unpaid'");
    add('Orders', 'pay_ref', 'TEXT');
    add('Orders', 'paid_at', 'TEXT');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON Users(email) WHERE email IS NOT NULL');
    db.exec(`CREATE TABLE IF NOT EXISTS Addresses (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL REFERENCES Users(username) ON DELETE CASCADE ON UPDATE CASCADE,
        recipient  TEXT NOT NULL,
        phone      TEXT NOT NULL,
        detail     TEXT NOT NULL,
        district   TEXT NOT NULL,
        province   TEXT NOT NULL,
        is_default INTEGER NOT NULL DEFAULT 0
    )`);
    db.exec('CREATE INDEX IF NOT EXISTS idx_addr_user ON Addresses(username)');
}

function openDatabase(file) {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
    const db = new Database(file);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.exec(SCHEMA);
    migrate(db);
    return db;
}

function seedProducts() {
    return JSON.parse(fs.readFileSync(path.join(__dirname, 'seed', 'products.json'), 'utf8'));
}

function insertProduct(db, p) {
    const stock = Number.isInteger(p.stock) ? p.stock : 15 + (p.id * 7) % 60;   // tồn kho mẫu 15-74
    const active = p.active === 0 ? 0 : 1;
    return db.prepare(`INSERT INTO Products (id, name, category, price, old_price, discount, specs, image, description, stock, active)
        VALUES (@id, @name, @category, @price, @oldPrice, @discount, @specs, @image, @description, @stock, @active)`).run({ ...p, stock, active });
}

// Dữ liệu mẫu ban đầu (chỉ chạy khi DB còn trống)
async function seedIfEmpty(db, clock, opts = {}) {
    const hasProducts = db.prepare('SELECT COUNT(*) c FROM Products').get().c > 0;
    const hasUsers = db.prepare('SELECT COUNT(*) c FROM Users').get().c > 0;
    const adminPassword = opts.adminPassword || '123';
    const customerPassword = opts.customerPassword || '123';

    if (!hasProducts) {
        db.transaction(() => { seedProducts().forEach(p => insertProduct(db, p)); })();
    }
    if (!hasUsers) {
        const now = clock.now();
        const ins = db.prepare('INSERT INTO Users (username, password_hash, full_name, phone, role, created_at, email, birthday, gender) VALUES (?,?,?,?,?,?,?,?,?)');
        ins.run('admin', await hashPassword(adminPassword), 'Quản Trị Viên Hệ Thống', '0900000001', 'admin', now, 'admin@technova.vn', null, null);
        ins.run('khach', await hashPassword(customerPassword), 'Nguyễn Trịnh Hải', '0988123456', 'customer', now, 'khach@example.com', '2000-01-15', 'Nam');
        db.prepare('INSERT INTO Addresses (username, recipient, phone, detail, district, province, is_default) VALUES (?,?,?,?,?,?,1)').run('khach', 'Nguyễn Trịnh Hải', '0988123456', 'Số 123, Đường Xuân Thủy', 'Quận Cầu Giấy', 'Hà Nội');
        db.prepare(`INSERT INTO Orders (id, username, customer_name, phone, address, created_ms, date_str, payment, status, subtotal, discount, coupon, total, is_demo)
            VALUES ('ĐH-202601','khach','Nguyễn Trịnh Hải','0988123456','Quận Cầu Giấy, Hà Nội',?, '10/11/2026 14:30','Chuyển khoản ngân hàng (VietQR)','Đang giao hàng',28280000,0,NULL,28280000,0)`).run(now);
        const insItem = db.prepare('INSERT INTO OrderItems (order_id, name, qty, price) VALUES (?,?,?,?)');
        insItem.run('ĐH-202601', 'Laptop Gaming ASUS TUF Gaming F16 (2026)', 1, 23990000);
        insItem.run('ĐH-202601', 'Màn Hình Gaming VSP AiVision 27" 2K QHD IPS 170Hz', 1, 4290000);
    }
    if (db.prepare('SELECT COUNT(*) c FROM FlashSales').get().c === 0) seedFlashSales(db, clock);
    topUpCatalog(db, clock);
}

// Nâng cấp DB cũ: thêm các sản phẩm mới theo tên (không đụng sản phẩm đã có / đã sửa) và bổ sung Flash Sale. Chỉ chạy 1 lần.
function topUpCatalog(db, clock) {
    db.exec('CREATE TABLE IF NOT EXISTS Meta (k TEXT PRIMARY KEY, v TEXT)');
    const KEY = 'catalog_v2';
    if (db.prepare('SELECT 1 FROM Meta WHERE k=?').get(KEY)) return;
    db.transaction(() => {
        const names = new Set(db.prepare('SELECT name FROM Products').all().map(r => r.name));
        const ins = db.prepare(`INSERT INTO Products (name, category, price, old_price, discount, specs, image, description, stock, active)
            VALUES (@name, @category, @price, @oldPrice, @discount, @specs, @image, @description, @stock, 1)`);
        seedProducts().forEach(p => { if (!names.has(p.name)) ins.run({ ...p, stock: 15 + (p.id * 7) % 60 }); });
        const perSlot = db.prepare('SELECT slot, COUNT(*) c FROM FlashSales GROUP BY slot').all();
        const have = new Set(db.prepare('SELECT product_id, slot FROM FlashSales').all().map(r => r.product_id + ':' + r.slot));
        const prods = db.prepare('SELECT id, price FROM Products WHERE active = 1 ORDER BY id').all();
        const addF = db.prepare('INSERT OR IGNORE INTO FlashSales (product_id, slot, flash_price, qty, sold, sold_date) VALUES (?,?,?,?,0,?)');
        let k = 100;
        for (let slot = 0; slot < 4; slot++) {
            let c = (perSlot.find(r => r.slot === slot) || { c: 0 }).c;
            while (c < FLASH_PER_SLOT && prods.length) {
                const p = prods[(k * 11 + slot * 3) % prods.length]; k++;
                if (have.has(p.id + ':' + slot)) continue;
                have.add(p.id + ':' + slot);
                const pct = [10, 12, 15, 18, 20, 25][k % 6];
                addF.run(p.id, slot, Math.max(1000, Math.round(p.price * (1 - pct / 100) / 1000) * 1000), 6 + (k % 4) * 3, clock.today());
                c++;
            }
        }
        db.prepare('INSERT INTO Meta (k, v) VALUES (?, ?)').run(KEY, '1');
    })();
}

const FLASH_PER_SLOT = 6;

function seedFlashSales(db, clock) {
    const prods = db.prepare('SELECT id, price FROM Products ORDER BY id').all();
    if (!prods.length) return;
    const pcts = [15, 20, 12, 18, 25, 10, 22, 16, 14, 30, 12, 20];
    const qtys = [10, 15, 20, 8, 12, 10, 15, 20, 6, 10, 8, 12];
    const PER_SLOT = FLASH_PER_SLOT;
    const ins = db.prepare('INSERT OR IGNORE INTO FlashSales (product_id, slot, flash_price, qty, sold, sold_date) VALUES (?,?,?,?,?,?)');
    let k = 0;
    for (let slot = 0; slot < 4; slot++) {
        for (let j = 0; j < PER_SLOT; j++) {
            const p = prods[(k * 7 + 2) % prods.length];
            const pct = pcts[k % pcts.length];
            let fp = Math.round(p.price * (1 - pct / 100) / 1000) * 1000;
            if (fp >= p.price) fp = Math.max(1000, p.price - 1000);
            const qty = qtys[k % qtys.length];
            const started = slot <= clock.slot();   // khung chưa mở thì chưa có ai mua
            const sold = !started ? 0 : (j % 3 === 0 ? Math.floor(qty * 0.6) : (j % 3 === 1 ? Math.floor(qty * 0.3) : 0));
            ins.run(p.id, slot, fp, qty, sold, clock.today());
            k++;
        }
    }
}

module.exports = { openDatabase, seedIfEmpty, seedFlashSales, seedProducts, insertProduct, makeClock, hashPassword, verifyPassword, DUMMY_HASH, FLASH_SLOT_HOURS, pad2 };
