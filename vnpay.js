/* Tích hợp cổng thanh toán VNPay (API 2.1.0) - ký HMAC-SHA512.
 * Cấu hình qua biến môi trường:
 *   VNPAY_TMN_CODE, VNPAY_HASH_SECRET  (lấy khi đăng ký sandbox tại https://sandbox.vnpayment.vn/devreg/)
 *   VNPAY_URL        (mặc định: sandbox https://sandbox.vnpayment.vn/paymentv2/vpcpay.html)
 *   PUBLIC_URL       (địa chỉ web công khai, vd https://abc.ngrok.app - dùng cho Return URL / IPN)
 * Không có TMN_CODE/HASH_SECRET -> chạy chế độ "giả lập" (trang thanh toán mô phỏng, cùng cơ chế ký) để demo.
 */
const crypto = require('crypto');

const SANDBOX_URL = 'https://sandbox.vnpayment.vn/paymentv2/vpcpay.html';
const enc = v => encodeURIComponent(v).replace(/%20/g, '+');

function sortedQuery(params) {
    return Object.keys(params).filter(k => params[k] !== undefined && params[k] !== null && params[k] !== '')
        .sort().map(k => enc(k) + '=' + enc(String(params[k]))).join('&');
}
function sign(params, secret) {
    const p = { ...params }; delete p.vnp_SecureHash; delete p.vnp_SecureHashType;
    return crypto.createHmac('sha512', secret).update(Buffer.from(sortedQuery(p), 'utf-8')).digest('hex');
}
function verify(params, secret) {
    const given = String(params.vnp_SecureHash || '').toLowerCase();
    const want = sign(params, secret);
    return given.length === want.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(want));
}
function stamp(d) {   // yyyyMMddHHmmss theo giờ VN; d là Date đã cộng offset, đọc bằng getUTC*
    const p = n => String(n).padStart(2, '0');
    return d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
}
const txnRef = (orderId, ms) => 'DH' + String(orderId).replace(/\D/g, '') + 'T' + ms;
const orderIdFromRef = ref => { const m = /^DH(\d+)T\d+$/.exec(String(ref || '')); return m ? 'ĐH-' + m[1] : null; };

function config(env = process.env) {
    const tmn = env.VNPAY_TMN_CODE || '', secret = env.VNPAY_HASH_SECRET || '';
    const live = !!(tmn && secret);
    return { live, tmn: live ? tmn : 'TECHNOVA_DEMO', secret: live ? secret : (env.VNPAY_MOCK_SECRET || 'technova-demo-secret'),
        url: env.VNPAY_URL || SANDBOX_URL, publicUrl: (env.PUBLIC_URL || '').replace(/\/+$/, '') };
}

function buildPaymentUrl(cfg, { orderId, amount, ip, vnNow, nowMs, returnUrl, mockUrl }) {
    const params = {
        vnp_Version: '2.1.0', vnp_Command: 'pay', vnp_TmnCode: cfg.tmn, vnp_Amount: Math.round(amount) * 100,
        vnp_CreateDate: stamp(vnNow), vnp_CurrCode: 'VND', vnp_IpAddr: String(ip || '127.0.0.1').replace(/^::ffff:/, '').replace('::1', '127.0.0.1'),
        vnp_Locale: 'vn', vnp_OrderInfo: 'Thanh toan don hang ' + String(orderId).replace(/\D/g, ''), vnp_OrderType: 'other',
        vnp_ReturnUrl: returnUrl, vnp_TxnRef: txnRef(orderId, nowMs),
        vnp_ExpireDate: stamp(new Date(vnNow.getTime() + 15 * 60000))
    };
    const q = sortedQuery(params) + '&vnp_SecureHash=' + sign(params, cfg.secret);
    return (cfg.live ? cfg.url : mockUrl) + '?' + q;
}

module.exports = { config, sign, verify, sortedQuery, buildPaymentUrl, orderIdFromRef, stamp, txnRef };
