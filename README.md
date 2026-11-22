# TechNova – website bán sản phẩm công nghệ (Node.js + Express + SQLite)

Frontend (giao diện) và backend (máy chủ + cơ sở dữ liệu) chạy chung một lệnh.

## Chạy

Cần cài [Node.js](https://nodejs.org) **bản 22 trở lên** (bản LTS mới nhất là được). Thư viện SQLite đã kèm sẵn bản dựng cho Windows, macOS và Linux nên không cần cài trình biên dịch.

```bash
npm install
npm start
```

Mở `http://localhost:3000`. Khi chạy, màn hình in thêm địa chỉ dạng `http://192.168.x.x:3000`:
mở địa chỉ đó trên **điện thoại cùng Wi-Fi** là xem được (nếu không vào được, tạm tắt tường lửa
hoặc cho phép Node.js qua tường lửa).

Tài khoản mẫu: `admin / 123` (quản trị) và `khach / 123` (khách hàng).
Trước khi cho người khác truy cập, hãy đặt mật khẩu admin riêng:

```bash
# macOS / Linux
ADMIN_PASSWORD='MatKhauManh2026' npm start
# Windows PowerShell
$env:ADMIN_PASSWORD='MatKhauManh2026'; npm start
```
(Mật khẩu admin chỉ được áp dụng lần đầu tạo cơ sở dữ liệu; muốn đổi sau đó thì đăng nhập admin và dùng nút "Đổi mật khẩu".)

Các biến môi trường khác: `PORT` (mặc định 3000), `HOST`, `DB_FILE` (đường dẫn file SQLite),
`TRUST_PROXY=1` và `COOKIE_SECURE=1` (khi đặt sau HTTPS như Render/Railway/Nginx).

## Cấu trúc

| Tệp | Vai trò |
|---|---|
| `server.js` | Máy chủ Express: API đăng nhập, giỏ hàng, đặt hàng, Flash Sale, đánh giá, quản trị |
| `db.js` | Tạo bảng SQLite, dữ liệu mẫu, mã hóa mật khẩu (scrypt), giờ Việt Nam |
| `seed/products.json` | 64 sản phẩm gốc |
| `public/index.html` | Giao diện (một tệp HTML/CSS/JS), gọi API qua `fetch` |
| `data/technova.db` | Cơ sở dữ liệu (tự tạo, xóa file này để về dữ liệu ban đầu) |
| `test/api.test.js` | 59 kiểm tra tự động cho API: `npm test` |

Bảng SQL: `Users, Sessions, Products, FlashSales, Orders, OrderItems, Carts, Reviews, SecurityLog, LoginAttempts`.

## Những gì máy chủ tự quyết định (trình duyệt không thể làm giả)

- Phiên đăng nhập bằng cookie `HttpOnly` + `SameSite`; tự hết hạn sau 30 phút không hoạt động (admin 15 phút).
- Mật khẩu băm `scrypt` + salt riêng; khóa đăng nhập khi sai 5 lần (60 giây, tăng dần); chính sách mật khẩu.
- Phân quyền: mọi API quản trị kiểm tra `role = admin` ở máy chủ; khách chỉ thấy đơn và giỏ của chính mình.
- Giá, Flash Sale (khung giờ, số suất còn lại), mã giảm giá và tổng tiền do máy chủ tính lại khi đặt hàng.
- Chống CSRF (kiểm tra `Origin` + header riêng), giới hạn tần suất, header bảo mật (CSP, nosniff, ...).
- Nhật ký bảo mật lưu trong bảng `SecurityLog`, admin xem ở tab "7. Nhật ký bảo mật".

## Đưa lên Internet (tùy chọn)

Dùng được trên Render, Railway, Fly.io hoặc một VPS: lệnh chạy là `npm start`, đặt
`TRUST_PROXY=1`, `COOKIE_SECURE=1`, `ADMIN_PASSWORD`, và gắn ổ đĩa lưu trữ cho thư mục `data/`
(nếu không, file SQLite sẽ mất mỗi lần dịch vụ khởi động lại).

## Bản chạy độc lập (không cần máy chủ)

`ptda.html` ở thư mục ngoài là bản cũ chạy hoàn toàn trong trình duyệt (dữ liệu trong localStorage),
chỉ dùng để demo; không có bảo mật thật.


## Đối chiếu Product Backlog (User Story) và kịch bản BDD

Tất cả 27 User Story / 16 Epic đã có trong hệ thống. Kiểm thử tự động theo từng kịch bản: `npm test`
(`test/scenarios.test.js` đặt tên theo Epic, ví dụ "E04 sai mật khẩu → Mật khẩu xác nhận không chính xác").

| Epic | Chức năng | Cách dùng / API |
|---|---|---|
| 01 Thêm tài khoản | Đăng ký bằng Họ tên, **Email**, Mật khẩu, Nhập lại mật khẩu, SĐT (email dùng để đăng nhập) | `POST /api/auth/register` |
| 02 Xem tài khoản | Hồ sơ (họ tên, email, SĐT, địa chỉ mặc định, ngày sinh, giới tính); **Sổ địa chỉ**; chưa đăng nhập → báo "Vui lòng đăng nhập…" | Menu tên tài khoản → "Tài khoản của tôi", đường dẫn `#/tai-khoan` |
| 03 Cập nhật tài khoản | Sửa hồ sơ, thêm/sửa/xóa/đặt mặc định địa chỉ | `PUT /api/account`, `/api/addresses` |
| 04 Xóa tài khoản | Nhập đúng mật khẩu + lý do; đơn đang chờ tự hủy, đơn cũ được ẩn danh | `POST /api/account/delete` |
| 05 Thêm sản phẩm | Tên, danh mục, giá, **tồn kho**, mô tả, ảnh (dán link hoặc **tải tệp** JPG/PNG/GIF/WEBP ≤ 2MB) | Quản trị → Sản phẩm |
| 06 Xem sản phẩm | Danh sách (Còn hàng/Hết hàng), chi tiết + tồn kho, tìm kiếm, lọc giá, đường dẫn `#/san-pham/<id>` | |
| 07 Cập nhật sản phẩm | Sửa thông tin; sửa nhanh **tồn kho** ngay trong bảng | `PATCH /api/admin/products/:id/stock` |
| 08 Xóa / ngừng bán | Nút "Ngừng bán" (có hộp thoại xác nhận, ẩn khỏi cửa hàng) hoặc Xóa | `PATCH /api/admin/products/:id/status` |
| 09–12 Giỏ hàng | Thêm, đổi số lượng, xóa (có xác nhận), chặn vượt tồn kho, giỏ trống có nút "Tiếp tục mua sắm" | |
| 13 Thêm đơn hàng | Chọn địa chỉ từ sổ địa chỉ, kiểm tra SĐT, đặt xong mở trang chi tiết đơn; tồn kho tự trừ | `POST /api/orders` |
| 14 Xem đơn hàng | Danh sách + "Xem chi tiết"; đơn không tồn tại/không phải của mình → cùng một thông báo | `GET /api/orders/:id`, `#/don-hang/<mã>` |
| 15 Cập nhật đơn hàng | Admin đổi trạng thái theo luật (không đổi ngược, đơn đã giao/đã hủy bị khóa); khách sửa thông tin nhận hàng khi còn "Chờ xác nhận" | `PATCH /api/admin/orders/:id/status`, `PUT /api/orders/:id/shipping` |
| 16 Xóa đơn hàng | Khách hủy kèm lý do khi còn "Chờ xác nhận"; hủy xong hoàn lại tồn kho | `POST /api/orders/:id/cancel` |

Quy ước trạng thái đơn: Chờ xác nhận → Đang giao hàng → Đã giao thành công (hoặc Đã hủy).
Tài khoản mẫu đăng nhập được bằng email: `admin@technova.vn` / `khach@example.com` (mật khẩu như cũ).
Cơ sở dữ liệu cũ được nâng cấp tự động khi chạy lại (thêm cột email, tồn kho, bảng địa chỉ…).


## Danh mục sản phẩm
Cửa hàng có sẵn 216 sản phẩm (5 danh mục), mỗi khung Flash Sale có 6 sản phẩm. Với DB cũ, lần chạy đầu tiên sẽ tự thêm sản phẩm mới theo tên (không ghi đè dữ liệu đã sửa). Muốn dữ liệu sạch: xóa `data/technova.db` rồi chạy lại.

## Thanh toán VNPay
Chọn "Thanh toán online qua VNPay" khi đặt hàng → **mở tab mới** hiện cổng VNPay (có mã QR, đồng hồ 15 phút) → quét/xác nhận thanh toán → tab cửa hàng tự cập nhật "Đã thanh toán" (không cần tải lại). Ở chế độ giả lập, quét QR bằng điện thoại cùng Wi-Fi hoặc bấm nút "Giả lập quét mã". Đơn chưa thanh toán có nút "Thanh toán ngay qua VNPay" trong chi tiết đơn.

- **Chạy thử ngay (không cần tài khoản):** không đặt biến gì cả, hệ thống dùng trang VNPay giả lập (cùng cơ chế ký HMAC-SHA512).
- **Dùng VNPay sandbox thật:** đăng ký tại https://sandbox.vnpayment.vn/devreg/ để lấy `TMN Code` và `Hash Secret`, rồi chạy:
  - PowerShell: `$env:VNPAY_TMN_CODE="..."; $env:VNPAY_HASH_SECRET="..."; npm start`
  - Nếu cần IPN từ VNPay gọi về máy bạn, dùng ngrok và đặt thêm `PUBLIC_URL=https://xxxx.ngrok-free.app` (đặt cả Return URL/IPN trên trang quản trị sandbox: `/api/payment/vnpay/return` và `/api/payment/vnpay/ipn`).
  - Thẻ test sandbox: ngân hàng NCB, số thẻ 9704198526191432198, tên NGUYEN VAN A, ngày phát hành 07/15, OTP 123456.
- Máy chủ tự kiểm tra chữ ký, số tiền và mã đơn; Return/IPN lặp lại không bị tính hai lần.
