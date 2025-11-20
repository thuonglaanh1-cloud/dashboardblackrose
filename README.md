# Telegram Group-Gated Login

Trang đăng nhập dùng Telegram Login Widget, chỉ cho phép thành viên một nhóm Telegram được truy cập. Backend xác thực chữ ký Telegram và kiểm tra membership qua Bot API.

## Cấu hình
1. Tạo bot Telegram và lấy token.
2. Thêm bot vào nhóm cần bảo vệ (làm admin để gọi `getChatMember`).
3. Lấy `chat_id` của nhóm (dạng `-100...`).
4. Sao chép `.env.example` thành `.env` và điền:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_BOT_USERNAME` (không có ký tự `@`)
   - `TELEGRAM_GROUP_ID`
   - `JWT_SECRET` (chuỗi bất kỳ dùng ký session JWT)
   - `PORT` (tuỳ chọn)

## Chạy
```bash
npm install
npm run dev
# mở http://localhost:3000 và đăng nhập bằng Telegram
```

Sau khi đăng nhập thành công, backend phát hành JWT lưu trong cookie `blackrose_session`. Điều này cho phép bạn truy cập `/dashboard` và gọi `/api/me`. Chọn “Log out” để xoá cookie.

## Luồng hoạt động
- Frontend gọi Telegram Login Widget → gửi `authData` lên `/api/auth/telegram`.
- Backend kiểm tra `hash` bằng HMAC SHA256 với `BOT_TOKEN`, sau đó gọi `getChatMember` để chắc chắn user thuộc nhóm.
- Nếu hợp lệ, backend phát hành JWT (ký bằng `JWT_SECRET`) và đặt cookie HttpOnly → user được chuyển tới `/dashboard`.
- `/api/me` trả thông tin user dựa trên token; `/api/logout` xoá cookie.

## Tùy biến
- Thay đổi copy/biểu tượng trong `public/index.html`.
- Thêm xử lý redirect thực tế sau khi đăng nhập ở frontend (`/dashboard`).
- Thêm middleware session hoặc JWT tuỳ hệ thống của bạn.
