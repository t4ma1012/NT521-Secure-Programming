# Security Requirements – `json_search()`

> Bước 1 – Yêu cầu 3 (phần 2/2): Các yêu cầu bảo mật được phát biểu từ [`THREAT_MODEL.md`](THREAT_MODEL.md).
> Mỗi yêu cầu đều **kiểm chứng được** và là căn cứ để viết security test trong `test_json_search.py` ở bước sau.

## 1. Phạm vi

- **Đối tượng**: hàm `json_search(key, data, role)` trong `recursive_json_search.py`.
- **Dữ liệu**: phản hồi API giám sát hạ tầng mạng (`test_data.py`).
- **Chính sách phân quyền**: `policy.py`

| Trường (`key`) | Role được phép |
|---|---|
| `apiKey` | `admin` |
| `managementIpAddress` | `admin`, `operator` |
| `issueSummary` | `admin`, `operator`, `viewer` |

- **Tập role hợp lệ**: `{"admin", "operator", "viewer"}`.

## 2. Danh sách Security Requirements

Từ khoá **PHẢI / KHÔNG ĐƯỢC / NÊN** mang nghĩa tương ứng MUST / MUST NOT / SHOULD (RFC 2119).

### SR-01 – Kiểm soát truy cập theo trường (Access control per field)

> **Hệ thống chỉ trả về giá trị của trường X cho các role nằm trong danh sách `POLICY[X]`. Với mọi role không nằm trong danh sách đó, hàm PHẢI trả về danh sách rỗng `[]`.**

- **Giảm thiểu**: T1, T2, T4 (Information Disclosure, Elevation of Privilege)
- **Tiêu chí chấp nhận**:

| Lời gọi | Kết quả kỳ vọng |
|---|---|
| `json_search("apiKey", data, role="admin")` | `["SNMP-COMMUNITY-STRING-7f3a9c"]` |
| `json_search("apiKey", data, role="operator")` | `[]` |
| `json_search("apiKey", data, role="viewer")` | `[]` |
| `json_search("managementIpAddress", data, role="operator")` | `["10.10.20.21"]` |
| `json_search("managementIpAddress", data, role="viewer")` | `[]` |
| `json_search("issueSummary", data, role="viewer")` | `["Network Device 10.10.20.82 Is Unreachable From Controller"]` |

- Việc kiểm tra quyền PHẢI diễn ra **trước** khi trả kết quả (tốt nhất là trước khi duyệt dữ liệu), không phụ thuộc vào vị trí/độ sâu của trường trong JSON.

### SR-02 – Mặc định từ chối (Deny by default / Fail-closed)

> **Với trường không được định nghĩa trong `POLICY`, hàm PHẢI từ chối truy cập (trả `[]`) đối với mọi role, trừ khi trường đó được bổ sung tường minh vào `POLICY`.**

- **Giảm thiểu**: T3
- **Tiêu chí chấp nhận**:
  - `json_search("serialNumber", data, role="viewer")` → `[]`
  - `json_search("macAddress", data, role="operator")` → `[]`
  - `json_search("XY&^$#*@!1234%^&", data, role="admin")` → `[]` (key không tồn tại)
- *Ghi chú*: nếu nhóm quyết định cho phép admin đọc mọi trường, quy tắc đó PHẢI được ghi tường minh trong `policy.py`, không được ngầm định trong code.

### SR-03 – Kiểm tra tính hợp lệ của role (Input validation)

> **Hàm PHẢI chỉ chấp nhận `role` có kiểu `str` và khớp chính xác (phân biệt hoa thường, không trim) một phần tử trong tập role hợp lệ. Mọi giá trị khác PHẢI bị từ chối (trả `[]`). Tham số `role` KHÔNG ĐƯỢC có giá trị mặc định mang đặc quyền.**

- **Giảm thiểu**: T4, T5, T6
- **Tiêu chí chấp nhận** – tất cả đều trả `[]` khi tra `apiKey`:

| Giá trị `role` | Lý do |
|---|---|
| `None` | thiếu role |
| `""` | rỗng |
| `"Admin"`, `"ADMIN"` | sai hoa thường |
| `" admin"`, `"admin "`, `"admin\x00"` | có ký tự thừa |
| `"superuser"`, `"root"` | role không tồn tại |
| `["admin"]`, `{"admin"}` | sai kiểu dữ liệu |
| Object có `__eq__` luôn trả `True` | chống bypass toán tử `in` |

- Gọi `json_search("apiKey", data)` (không truyền role) KHÔNG ĐƯỢC trả về credential.

### SR-04 – Toàn vẹn dữ liệu và chính sách (Integrity)

> **Hàm KHÔNG ĐƯỢC thay đổi (mutate) đối tượng `data` đầu vào. Bảng `POLICY` NÊN được biểu diễn ở dạng bất biến để không thể bị sửa đổi lúc chạy.**

- **Giảm thiểu**: T7
- **Tiêu chí chấp nhận**:
  - `copy.deepcopy(data)` trước lời gọi == `data` sau lời gọi, với mọi role.
  - Thử `POLICY["apiKey"].append("viewer")` gây lỗi (nếu dùng `tuple`/`frozenset`/`MappingProxyType`), hoặc hàm không bị ảnh hưởng bởi thay đổi đó.

### SR-05 – Chống từ chối dịch vụ do dữ liệu lồng sâu (Availability)

> **Hàm PHẢI xử lý được JSON lồng sâu mà không làm sập tiến trình (không ném `RecursionError` ra ngoài), bằng cách duyệt lặp (iterative, dùng stack/queue) hoặc giới hạn độ sâu tối đa.**

- **Giảm thiểu**: T9
- **Tiêu chí chấp nhận**:
  - Với JSON lồng 5000 cấp (`{"a": {"a": ... {"issueSummary": "x"}}}`), lời gọi với `role="viewer"` kết thúc bình thường và trả về kết quả xác định (`["x"]` nếu duyệt lặp, hoặc `[]` nếu vượt giới hạn độ sâu đã ghi rõ).

### SR-06 – Từ chối không để lộ thông tin (Safe failure)

> **Khi từ chối truy cập, hàm PHẢI trả `[]` một cách "im lặng": KHÔNG ĐƯỢC ném exception hoặc trả thông điệp chứa giá trị của trường, nội dung `POLICY`, hay gợi ý role nào có quyền.**

- **Giảm thiểu**: T10
- **Tiêu chí chấp nhận**:
  - Kết quả với role không có quyền giống hệt kết quả với key không tồn tại (`[]`) → kẻ tấn công không phân biệt được "không có quyền" với "không có dữ liệu".
  - Không có exception nào được ném ra trong các ca kiểm thử của SR-01, SR-02, SR-03.

### SR-07 – Ghi nhật ký truy cập trường nhạy cảm (Auditability) — *NÊN*

> **Hàm NÊN ghi log (qua module `logging`) mỗi lần truy vấn tới trường nhạy cảm (`apiKey`, `managementIpAddress`) gồm: key, role, kết quả cho phép/từ chối. Log KHÔNG ĐƯỢC chứa giá trị của trường.**

- **Giảm thiểu**: T8
- **Tiêu chí chấp nhận** (dùng `assertLogs`):
  - Lời gọi `json_search("apiKey", data, role="viewer")` sinh bản ghi log mức `WARNING` chứa `apiKey`, `viewer`, `denied`.
  - Không bản ghi log nào chứa chuỗi `SNMP-COMMUNITY-STRING-7f3a9c`.

## 3. Ma trận truy vết (Traceability Matrix)

| Requirement | Threat (STRIDE) | Tài sản | Loại test sẽ viết |
|---|---|---|---|
| SR-01 | T1, T2 (I), T4 (E) | A1, A2 | Security test – role không có quyền → `[]` |
| SR-02 | T3 (I) | A3–A6 | Security test – key ngoài `POLICY` → `[]` |
| SR-03 | T4, T5 (E), T6 (S) | A1, A2 | Security test – role dị dạng / sai kiểu → `[]` |
| SR-04 | T7 (T) | A8, dữ liệu | Unit test – `data` không bị thay đổi |
| SR-05 | T9 (D) | Tính sẵn sàng | Robustness test – JSON lồng sâu |
| SR-06 | T10 (I) | A1, A8 | Security test – không có exception, kết quả đồng nhất |
| SR-07 | T8 (R) | A1, A2 | Unit test với `assertLogs` |

## 4. Yêu cầu chức năng liên quan (để đối chiếu)

Các yêu cầu bảo mật trên không được làm mất chức năng gốc:

- **FR-01**: Với role có quyền, hàm trả về **tất cả** giá trị của `key` ở mọi độ sâu, theo thứ tự duyệt (ví dụ `json_search("issueSummary", data, role="admin")` → `["Network Device 10.10.20.82 Is Unreachable From Controller"]`).
- **FR-02**: Key không tồn tại → `[]` (ví dụ `key2 = "XY&^$#*@!1234%^&"`).
- **FR-03**: Hàm duyệt được cả `dict` và `list` lồng nhau.
