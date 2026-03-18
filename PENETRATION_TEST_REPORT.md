# BÁO CÁO KIỂM THỬ BẢO MẬT

**Dự án:** FPT Event Management System

**Ngày thực hiện:** 14/03/2026

**Người thực hiện:** Phong (Pentester)

**Mục tiêu:** fptevent.local

---

## 1. TÓM TẮT SƠ BỘ BÁO CÁO

*(Sẽ viết cuối cùng. Tóm tắt hệ thống có an toàn để deploy lên AWS không, lỗi nào nguy hiểm nhất).*

## 2. PHẠM VI & PHƯƠNG PHÁP

* **Giai đoạn kiểm thử:** Hệ thống đang trong giai đoạn phát triển và tích hợp cục bộ (Local Development), chưa được DevOps triển khai lên hạ tầng thực tế (AWS Cloud). Đợt kiểm thử này mang tính chất **Shift-Left Security** nhằm triệt tiêu rủi ro từ sớm.
* **Hạ tầng hiện tại:** Kiến trúc Microservices được triển khai toàn bộ trên nền tảng Docker nội bộ.
* **Kịch bản giả định:** Kẻ tấn công được giả định là một cá nhân đã có quyền truy cập vào mạng nội bộ (LAN/Wi-Fi công ty) hoặc đã chiếm quyền điều khiển một thiết bị trong mạng (mô hình Assume Breach).
* **Phạm vi:** Các API và Web UI chạy trên Host `fptevent.local`, các port: `3000, 3306, 8080, 8081, 8082, 8083, 8084, 8085, 8086`.
* **Giới hạn kiểm thử:**
  - Chưa đánh giá rủi ro an toàn mạng nội bộ giữa các container (Container-to-Container lateral movement) trong trường hợp một node bị xâm nhập.
  - Chưa thể đánh giá bảo mật toàn diện `File Uploading Vulnerabilities` do môi trường Local thiếu cấu hình biến môi trường kết nối đến AWS S3.
* **Phương pháp:** Black-box/Grey-box testing từ xa qua mạng LAN, kết hợp White-box review cấu hình Docker.
* **Công cụ sử dụng:** Nmap, Burp Suite, OWASP ZAP, Trình duyệt web.

---

## 3. CHI TIẾT LỖ HỔNG KỸ THUẬT

### 3.1. Nhóm lỗi Cấu hình mội trường & Hạ tầng

#### 1. Architecture Misconfiguration `OWASP A02:2025 - Security Misconfiguration`

* **Mức độ:** Cao.
* **Mô tả:** File docker-compose.yml do Dev cung cấp cho môi trường Local đang bộc lộ tất cả các port của microservices (8081-8086) và Database (3306) ra ngoài 0.0.0.0 thay vì chỉ dùng mạng nội bộ Docker.
* **Proof of Concept (PoC):**
    1. Đứng từ máy tấn công (Kali Linux), thực hiện quét Nmap tới Host của máy chủ: `nmap -sV -sC -sS -v fptevent.local`.
    2. Kết quả trả về cho thấy cổng 3306 (MySQL 8.0.45)và các cổng 8081-8086 (Golang net/http) mở trạng thái `open` và phản hồi lại các request HTTP chưa xác thực.

    ![alt text](pentest_report_images/1.png)

    3. Mặc dù các API nội bộ không có tài liệu công khai, kẻ tấn công có thể dò tìm và gửi request HTTP trực tiếp vào cổng 8083 (Ticket Service), bỏ qua hoàn toàn API Gateway (8080).
    4. Thực thi lấy dữ liệu trái phép mà không cần bất kỳ token xác thực nào:
    `curl -i http://fptevent.local:8083/api/registrations/my-tickets -H "X-User-Id: 1" -H "X-User-Role: Admin"`
    5. API nội bộ trả về mã `200 OK` kèm theo toàn bộ dữ liệu vé của khách hàng dưới dạng JSON:

    ```JSON
      [
      {
          "ticketId": 179,
          "ticketCode": "TKT_1032_220_77",
          "eventName": "AWS re:Invent",
          "venueName": "Nhà văn hóa sinh viên Đại học Quốc gia Tp HCM",
          "startTime": "2026-02-10T09:00:00+07:00",
          "status": "BOOKED",
          "checkInTime": null,
          "checkOutTime": null,
          "category": "VIP",
          "categoryPrice": 250000,
          "seatCode": null,
          "buyerName": "Nguyễn Văn An",
          "purchaseDate": "2026-02-10T09:00:00+07:00"
      },
      {
          "ticketId": 39,
          "ticketCode": "iVBORw0KGgoAAA...[truncated_base64_string]...",                                            "eventName": "Buổi dạy Thư Pháp Ngày Xuân 2026",
          "venueName": "Nhà văn hóa sinh viên Đại học Quốc gia Tp HCM",
          "startTime": "2026-01-01T18:00:00+07:00",
          "status": "BOOKED",
          "checkInTime": null,
          "checkOutTime": null,
          "category": "STANDARD",
          "categoryPrice": 10000,
          "seatCode": null,
          "buyerName": "Nguyễn Văn An",
          "purchaseDate": "2026-01-01T18:00:00+07:00"
      }
      ]
    ```

* **Tác động:** Nếu hệ thống này được deploy trực tiếp lên AWS mà không tinh chỉnh lại, toàn bộ hạ tầng sẽ bị phơi bày ra Internet. Nguy hiểm hơn, kẻ tấn công có thể trực tiếp gửi request giả mạo đặc quyền (X-User-Role: Admin) vào các cổng nội bộ (như 8083) để đánh cắp dữ liệu kinh doanh cốt lõi (thông tin vé, khách hàng, doanh thu) mà không bị API Gateway ngăn chặn.
* **Khuyến nghị khắc phục:**
  * **Dev:** Sửa lại file docker-compose.yml local, gỡ bỏ ports: ở các service backend và database.
  * **DevOps:** Khi phác thảo kiến trúc AWS (VPC, Subnet), phải thiết kế Security Group chặt chẽ, chỉ mở port 80/443 ở lớp Load Balancer/API Gateway.
  
#### 2. Direct Database Compromise via Weak/Default Root Credentials `OWASP A07:2025 - Authentication Failures`

* **Mức độ:** Nghiêm trọng.
* **Mô tả:** Cơ sở dữ liệu MySQL (3306) không chỉ bị bộc lộ ra ngoài mà còn cho phép kết nối từ xa (remote access) vào tài khoản `root` với mật khẩu yếu. Kết hợp với việc cấu hình SSL lỏng lẻo, kẻ tấn công có thể dễ dàng chiếm toàn quyền kiểm soát hệ thống cơ sở dữ liệu.
* **Proof of Concept (PoC):**
    1. Kẻ tấn công sử dụng công cụ dòng lệnh MySQL kết nối thẳng từ máy Kali Linux vào máy chủ bằng tài khoản `root` và cờ `--skip-ssl`:
    `mysql -h fptevent.local -u root -p --skip-ssl`
    2. Đăng nhập thành công và thực thi truy cập trích xuất dữ liệu từ bảng `users` trong cơ sở dữ liệu `fpteventmanagement`:

    ```sql
    MySQL [(none)]> USE fpteventmanagement;
    MySQL [fpteventmanagement]> SELECT * FROM users;
    ```

    3. Kết quả trả về chứa toàn bộ thông tin người dùng:

    ![alt text](pentest_report_images/3.png)

* **Tác động:** Kẻ tấn công có toàn quyền kiểm soát dữ liệu 100%. Chúng có thể đọc, sửa, xóa toàn bộ thông tin dự án, thao túng số dư ví điện tử, trộm thông tin cá nhân và mang các chuỗi `password_hash` về máy tính cá nhân để tiến hành bẻ khóa ngoại tuyến (Offline Cracking).
* **Khuyến nghị khắc phục:**
  * **Dev:**
    * Cấu hình lại MySQL, tắt tính năng cho phép tài khoản `root` đăng nhập từ xa (chỉ cho phép `root@localhost`).
    * Thay đổi mật khẩu tài khoản `root` thành chuỗi mật khẩu mạnh và an toàn.
    * Áp dụng nguyên tắc Đặc quyền tối thiểu: Tạo một tài khoản MySQL riêng biệt (ví dụ: `fptevent_user`) chỉ có quyền thao tác (SELECT, INSERT, UPDATE) trên đúng database `fpteventmanagement` để cung cấp cho ứng dụng Backend, tuyệt đối không dùng tài khoản `root`.

#### 3. Sensitive Information Exposure via Development Server `OWASP A02:2025 - Security Misconfiguration`

* **Mức độ:** Cao.
* **Mô tả:** Qua quá trình rà quét hệ thống bằng công cụ OWASP ZAP, phát hiện mãy chủ frontend đang được vận hành bằng Development Vite thay vì bản build Production. Việc cấu hình như này trong giai đoạn đóng gói docker local khiến máy chủ không nén (`minify`) hay làm rối (`obfuscate`), mã nguồn mà trực tiếp phơi bày toàn bộ cấu trúc thư mục gốc, mã nguồn và danh sách thư viện gốc của dự án ra bên ngoài.
* **Proof of Concept (PoC):**
  1. Đứng từ máy tấn công (Kali Linux), sử dụng OWASP ZAP thực hiện thu thập các endpoint của mục tiêu `http://fptevent.local:3000`.
  2. Kết quả trả về hàng loạt các đường dẫn chứa mã nguồn gốc chưa qua biên dịch, bao gồm:
  - `http://fptevent.local:3000/src/App.tsx`
  - `http://fptevent.local:3000/src/pages/AdminDashboard.tsx`
  - `http://fptevent.local:3000/src/utils/imageUpload.ts`
  - Hàng loạt thư viện phụ thuộc tại `http://fptevent.local:3000/node_modules/.vite/deps/...`
  3. Kẻ tấn công có thể truy cập trực tiếp các file này trên trình duyệt và có thể phân tích logic hệ thống dễ dàng.
* **Tác động:**
  - **Source Code Disclousure:** Cung cấp cho kẻ tấn công bản đồ kiến trúc frontend hoàn chỉnh. Nhờ đó, chúng có thể dễ dàng phân tích các thuật toán kiểm tra tính hợp lệ nhằm chế tạo các payload qua mặt hệ thống phòng thủ.
  - **Suply Chain Exposure:** Việc lộ lọt các thư viện phụ thuộc sẽ giúp kẻ tấn công xác định được chính xác phiên bản của từng thư viện được sử dụng, từ đó đối chiếu với cac CVEs để tìm các lỗ hổng đã biết và tấn công khai thác.
* **Khuyến nghị khắc phục:**
  * **Dev:** Chỉnh sửa lại `Dockerfile` của frontend, tuyệt đối không sử dụng `npm run dev` để chạy container. Thay vào đó, sử dụng `npm run build`, sau đó sử dụng một Web Server (như Nginx alpine) để phục vụ thư mục `dist/` tĩnh được sinh ra.
  * **DevOps:** Khi thiết kế hạ tầng AWS, đảm bảo Frontend phải được host trên `AWS S3 kết hợp CloudFront`, chặn đứng hoàn toàn rủi ro trên môi trường Development khi đưa lên Production.

### 3.2. Nhóm lỗi Backend & API Services

#### 1. Internal Authentication Bypass & Data Exposure `OWASP A01:2025 - Broken Access Control`

* **Mức độ:** Nghiêm trọng.
* **Mô tả:** Hệ thống áp dụng cơ chế bảo mật thiếu an toàn (Security by Obscurity) cho các luồng giao tiếp nội bộ giữa các microservices. Qua rà soát mã nguồn và kiểm thử thực tế tại cổng 8081 (Auth/User Service), API nội bộ `/internal/user/profiles` chỉ dựa vào một HTTP Header tĩnh là `x-internal-call: true` để cấp quyền truy cập mà không có cơ chế xác minh danh tính mã hóa nào.
* **Proof of Concept (PoC):**
    1. Kẻ tấn công gửi một request HTTP GET trực tiếp vào cổng 8081, nhắm vào API nội bộ và giả mạo Headers được yêu cầu:
    `curl -i "http://fptevent.local:8081/internal/user/profiles?userIds=1" -H "x-internal-call: true"`
    2. Hệ thống bị đánh lừa và trả về mã `200 OK` kèm theo toàn bộ dữ liệu định danh PII của người dùng tương ứng:

    ```JSON
    [
      {
        "userId": 1,
        "fullName": "Nguyễn Văn An",
        "email": "an.nvse14001@fpt.edu.vn",
        "phone": "0901000100",
        "role": "STUDENT"
      }
    ]
    ```

* **Tác động:** Kẻ tấn công dễ dàng trích xuất toàn bộ cơ sở dữ liệu người dùng của dự án. Việc này gây rò rỉ thông tin về email, số điện thoại của người dùng, vi phạm nghiêm trọng các nguyên tắc bảo mật thông tin.
* **Khuyến nghị khắc phục:**
  * **Dev:** Loại bỏ việc kiểm tra quyền bằng Header tĩnh `x-internal-call`. Thiết lập cơ chế xác thực Service-to-Service an toàn. Phương án khả thi nhất hiện tại là sử dụng một **INTERNAL_SECRET_KEY** dùng chung (lưu trong file `.env`) để tạo hàm băm (**HMAC**) xác thực request, hoặc cấp phát một **Internal JWT** dành riêng cho các microservices giao tiếp với nhau.

#### 2. Missing Anti-Automation and Rate Limiting on Password Reset API `OWASP A06:2025 - Insecure Design`

* **Mức độ:** Cao.
* **Mô tả:** Qua quá trình phân tích mã nguồn Frontend và kiểm thử động, phát hiện tính năng "Quên mật khẩu" hoàn toàn không có cơ chế chống tự động hóa và giới hạn tần suất. Mã nguồn `src/pages/ResetPassword.tsx` không tích hợp Google reCAPTCHA. Phía Backend cũng không áp dụng giới hạn số lượng request gọi đến API gửi email OTP.
* **Proof of Concept (PoC):**
    1. Truy cập chức năng Quên mật khẩu trên giao diện frontend.
    2. Nhập 1 địa chỉ email bất kỳ và nhấn "Gửi mã OTP"
    3. Sử dụng BurpSuite để Intercept request `POST /api/forgot-password`.
    4. Đưa request này qua `Repeater` và thực hiện gửi hàng loạt 20 requests liên tục.
    5. Kết qua: toàn bộ 20 requests đều trả về `200 OK`, không có bất kỳ request nào bị chặn lại bởi lỗi `429 Too Many Requests` hay các cơ chế chống Spam khác.

    ![alt text](./pentest_report_images/4.png)

* **Tác động:**
  * **Email Spaming:** Kẻ tấn công có thể sử dụng công cụ tự động để gửi hàng ngàn requests OTP đến một hộp thư mục tiêu, gây gián đoạn công việc của nạn nhân.
  * **Resource Exhaustion:** Lạm dụng API này sẽ ép máy chủ Backend liên tục gọi đến dịch vụ email (SMTP/SES) gây rủi ro phát sinh chi phí không đáng có và tên miền bị đưa vào danh sách đen do hành vi gửi thư rác.
* **Khuyến nghị khắc phục:**
  * **Backend/API Gateway:** áp dụng cơ chế Rate Limiting cho endpoint `/api/forgot-password` (Giới hạn 1 IP hoặc 1 Email chỉ được yêu cầu gửi OTP tối đa 3 lần/giờ).
  * **Frontend & Backend:** Tích hợp Google reCaptcha vào form Quên mật khẩu và bắt buộc Backend phải xác thực token trước khi gửi email.

### 3.3. Nhóm lỗi Frontend & Client-Side

  #### Insecure Storage `OWASP A07:2025 - Authentication Failures`

  * **Mức độ:** Trung bình.
  * **Mô tả:** Hệ thống Frontend gặp phải 2 lỗi thiết kế nghiêm trọng trong việc quản lý phiên đăng nhập:
    * **Lưu trữ không an toàn:** Token JWT được lưu trữ tại `localStorage`. Trình duyệt cho phép bất kỳ mã JavaScript nào cũng có thể truy xuất vùng nhớ này, khiến hệ thống cực kỳ nhạy cảm với các cuộc tấn công Cross-Site Scripting (XSS).
    * **Client-Side Access Control Bypass:** Frontend sử dụng đối tượng `user` lưu dưới dạng JSON plain-text trong `localStorage` để quyết định hiển thị Menu và Route dành riêng cho Admin/Staff.
  * **Proof of Concept (PoC):**
    1. Đăng nhập vào hệ thống bằng tài khoản sinh viên (email: <an.nvse14001@fpt.edu.vn>; role: STUDENT).
    2. F12 mở Developer Tools ${\rightarrow}$ Application/Storage ${\rightarrow}$ Local Storage.
    3. Quan sát thấy JWT Token được lưu tại key `token`, thông tin người dùng lưu tại `user`.
    4. Thực hiện chỉnh sửa giá trị của key `user`, thay đổi `"role":"STUDENT"` thành `"role":"ADMIN"`.
    4. Tải lại trang (F5), hệ thống frontend bị đánh lừa và hiển thị toàn bộ giao diện, chức năng dành riêng cho Quản trị viên hệ thống.

    ![alt text](./pentest_report_images/5.png)

    5. Tuy nhiên, khi thực hiện tạo người dùng mới, hành vi đã bị backend chặn lại chính xác với mã `403 Forbidden` dựa trên JWT Token.
  * **Tác động:**
    * Token bị đánh cắp dễ dàng nếu phát sinh lỗi XSS ở bất kỳ đâu trên ứng dụng.
    * Mặc dù backend đã bảo vệ thành công dữ liệu, lỗi thiết kế frontend gây ra **lộ lọt bề mặt tấn công**. Kẻ tấn công có thể ánh xạ được toàn bộ thiết kế giao diện, cấu trúc các form, và thu thập các endpoint API nội bộ dành riêng cho Admin để chuẩn bị cho các chiến dịch tấn công khác.
  * **Khuyến nghị khắc phục:**
    * Lưu trữ JWT bằng `Cookies` với các flag `HttpOnly`, `Secure`, `SameSite=Strict` để ngăn chặn JavaScript truy cập.
    * Không lưu trữ trực tiếp `user` dưới dạng plain-text ở LocalStorage. Đề xuất cho frontend gọi một API định danh (`api/auth/me`) mỗi khi load trang nhạy cảm để xác minh quyền hạn từ backend trước khi render giao diện.

### 3.4. Nhóm lỗi Logic Nghiệp vụ



## 4. ĐIỂM SÁNG BẢO MẬT & THÔNG TIN BỔ SUNG

Môi trường hiện tại là Local Docker, do đó một số cấu hình mạng và mã hóa mang tính chất mặc định của nền tảng. Tuy nhiên, để chuẩn bị cho giai đoạn đưa hệ thống lên hạ tầng AWS Production, cần lưu ý các điểm sau:

* **Mã hóa đường truyền (In-Transit Encryption):** Các cổng giao tiếp của Frontend (3000) và API Gateway (8080) hiện đang chạy HTTP thuần (Plain-text). Khi lên AWS, **bắt buộc** phải cấu hình TLS/SSL (HTTPS) tại lớp Load Balancer (ALB) hoặc API Gateway để mã hóa toàn bộ lưu lượng giao tiếp với người dùng cuối, chống lại các cuộc tấn công nghe lén (Sniffing/MiTM).
* **Quản lý biến môi trường (Secrets Management):** Tuyệt đối không tái sử dụng các mật khẩu cơ sở dữ liệu hoặc `INTERNAL_SECRET_KEY` từ môi trường Local đưa lên Production. Cần sử dụng các dịch vụ chuyên dụng như AWS Secrets Manager hoặc Parameter Store để quản lý key thay vì hardcode trong file `.env`.
* **Kiểm soát phân quyền cấp API (Strict Authorization):** Mặc dù frontend bị vượt qua do lỗi lưu trữ LocalStorage, backend API vẫn thực hiện xác thực quyền (Role-based Access Control) cực kỳ chặt chẽ, các nổ lực nhằm leo thang đặc quyền đều bị chặn đứng với mã lỗi `403 Forbidden`.
* **Tích hợp thanh toán an toàn (Secure Payment Gateway):** Luồng tạo giao dịch thanh toán được thiết kế bảo mật. Chữ ký số được tính toán tại backend, ngăn chặn thành công tấn công thao túng tham số khi kẻ tấn công cố tình đổi giá vé trên đường truyền.