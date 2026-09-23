## Step 1 – Security Requirements & Threat Model

### Actors / Roles
- Dựa trên `policy.py`, hệ thống định nghĩa 3 role: `admin`, `operator`, `viewer`.
- Lưu ý: `recursive_json_search.py` và `test_json_search.py` hiện đang **rỗng** (chỉ có comment `# Fill the Python code in this file`) — hàm `json_search()` **chưa được implement**. Phần Actor/Role ở đây được suy ra từ `policy.py` (đặc tả), chưa phải từ hành vi thực tế của code.

### Sensitive Assets
- `apiKey` (`enrichmentInfo.connectedDevice[].deviceDetails.apiKey`) — chuỗi xác thực SNMP community string thật (`"SNMP-COMMUNITY-STRING-7f3a9c"`). Chỉ `admin` được phép theo `POLICY`.
- `managementIpAddress` (cùng nhánh `deviceDetails`) — IP quản trị thiết bị (`"10.10.20.21"`). `admin`, `operator` được phép.
- `issueSummary` (`enrichmentInfo.issueDetails.issue[].issueSummary`) — tóm tắt sự cố, ít nhạy cảm nhất, cả 3 role đều được phép.
- `test_data.py` còn có `key2 = "XY&^$#*@!1234%^&"` — đây là một **role không hợp lệ** dùng để test, không phải asset.

### Trust Boundary
- Ranh giới nằm giữa **caller** (người gọi `json_search(key, data, role)`, cung cấp `role`) và **dữ liệu JSON nội bộ** chứa `apiKey`/`managementIpAddress`.
- Vì `json_search()` chưa có code, chưa thể khẳng định ranh giới này có được kiểm soát hay không — đây là rủi ro thiết kế cần đặt yêu cầu bảo mật **trước khi code**, tránh trường hợp hàm chỉ tìm theo `key` mà bỏ qua tham số `role`.
- `role` phải được coi là input không tin cậy: hàm không được mặc định "tìm thấy `key` là trả về", mà phải luôn đối chiếu với `POLICY` trước khi trả kết quả.

### Threats
- **T1 – Information Disclosure:** Nếu `json_search()` không kiểm tra `role` với `POLICY[key]`, gọi `json_search("apiKey", data, role="viewer")` sẽ trả về đúng giá trị `apiKey` thật trong `test_data.py`, làm lộ SNMP community string ra ngoài phạm vi cho phép.
- **T2 – Elevation of Privilege:** Một `operator` (được phép xem `managementIpAddress` nhưng không được phép xem `apiKey`) vẫn có thể đọc được `apiKey` nếu hàm không phân biệt quyền theo từng key — hiệu quả tương đương `operator` "leo thang" lên quyền của `admin` đối với trường đó.

### Security Requirements
- **SR1:** Với mọi `key` có trong `POLICY`, hàm chỉ được trả về giá trị của `key` khi `role` nằm trong `POLICY[key]`; ngược lại phải trả về rỗng (`[]`/`None` tuỳ interface).
- **SR2:** Với `role` không tồn tại/không hợp lệ (ví dụ `key2 = "XY&^$#*@!1234%^&"` trong `test_data.py`), hàm phải xử lý như "không có quyền" và trả về rỗng, không được raise lỗi làm lộ thêm thông tin.
- **SR3:** Việc kiểm tra quyền theo SR1 phải áp dụng nhất quán tại **mọi vị trí** `key` xuất hiện trong cấu trúc JSON lồng nhau (dict/list ở bất kỳ độ sâu nào trong `test_data.py`), không chỉ ở lần khớp đầu tiên.

### Kết luận
Hiện `policy.py` đã định nghĩa rõ quy tắc phân quyền theo role, nhưng `recursive_json_search.py` chưa có bất kỳ dòng code nào để thực thi quy tắc đó — nghĩa là rủi ro Information Disclosure và Elevation of Privilege đối với `apiKey`/`managementIpAddress` hiện tại là **rủi ro thiết kế cần phòng trước**, chưa phải lỗi đã xác nhận trong code. Ba yêu cầu SR1–SR3 ở trên sẽ là căn cứ trực tiếp để viết security test ở Step 7 (`test_json_search.py`) trước khi implement hàm.

---

**Những file đã đọc:** `policy.py`, `recursive_json_search.py`, `test_data.py`, `test_json_search.py`
**Những file đã thay đổi:** `NONE`
