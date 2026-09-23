# Threat Model – `json_search()`

> Bước 1 – Yêu cầu 3 (phần 1/2): Mô hình hoá mối đe doạ theo STRIDE.
> Security Requirements được phát biểu từ tài liệu này nằm trong [`SECURITY_REQUIREMENTS.md`](SECURITY_REQUIREMENTS.md).

## 1. Bối cảnh hệ thống

`json_search(key, data, role)` (trong `recursive_json_search.py`) duyệt đệ quy một đối tượng JSON (dict/list lồng nhau) và trả về danh sách mọi giá trị ứng với `key`. Dữ liệu đầu vào là phản hồi của một **API giám sát hạ tầng mạng** (Cisco DNA Center – mẫu trong `test_data.py`). Hàm được dùng chung cho nhiều người dùng có vai trò khác nhau; quyền đọc từng trường được quy định trong `policy.py`:

```python
POLICY = {
    "apiKey":              ["admin"],
    "managementIpAddress": ["admin", "operator"],
    "issueSummary":        ["admin", "operator", "viewer"],
}
```

### Luồng dữ liệu (Data Flow)

```
 ┌──────────────┐  (1) key, role   ┌────────────────────────────┐  (3) đọc   ┌──────────────────────────┐
 │  Người dùng  │ ───────────────► │  json_search()             │ ─────────► │  Dữ liệu API giám sát    │
 │ admin/       │                  │  = Policy Enforcement Point│            │  (test_data.data)        │
 │ operator/    │ ◄─────────────── │  (2) tra POLICY[key]       │ ◄───────── │  chứa apiKey, IP, MAC... │
 │ viewer       │  (4) kết quả     └────────────────────────────┘            └──────────────────────────┘
 └──────────────┘                              │
        ▲                                      ▼
        │                              ┌──────────────┐
   TB-1 (ranh giới người dùng ↔ hàm)   │  policy.py   │
                                       └──────────────┘
                     TB-2 (ranh giới hàm ↔ dữ liệu nhạy cảm)
```

## 2. (a) Actor / Role và mục đích sử dụng

| Actor | Được phép gọi hàm? | Mục đích hợp lệ | Trường được phép đọc (theo `POLICY`) |
|---|---|---|---|
| **admin** | Có | Quản trị toàn bộ hạ tầng: cấu hình thiết bị, xử lý sự cố SNMP, cập nhật credential | `apiKey`, `managementIpAddress`, `issueSummary` |
| **operator** | Có | Vận hành NOC: xác định thiết bị lỗi, truy cập IP quản trị để khắc phục sự cố | `managementIpAddress`, `issueSummary` |
| **viewer** | Có | Theo dõi/báo cáo: xem tóm tắt sự cố trên dashboard | `issueSummary` |
| **Role không xác định / rỗng / `None`** | Không | – | Không trường nào |
| **Kẻ tấn công** (người dùng hợp lệ nhưng quyền thấp, hoặc thành phần gọi hàm bị chiếm quyền) | – | Thu thập credential, IP quản trị, thông tin định danh để tấn công hạ tầng | – |

## 3. (b) Tài sản nhạy cảm (Assets) trong dữ liệu trả về

| ID | Trường trong `test_data.py` | Ví dụ giá trị | Phân loại | Tác động nếu lộ |
|---|---|---|---|---|
| A1 | `apiKey` | `SNMP-COMMUNITY-STRING-7f3a9c` | **Bí mật – credential** | Dùng SNMP community string để đọc (và có thể ghi nếu là RW community) cấu hình thiết bị → chiếm quyền thiết bị mạng |
| A2 | `managementIpAddress` | `10.10.20.21` | **Hạn chế – địa chỉ mặt phẳng quản trị** | Xác định mục tiêu tấn công trực tiếp vào management plane (SSH/SNMP/HTTPS) |
| A3 | `actualServiceId`, `issueEntityValue` | `10.10.20.82` | Hạn chế | Lộ IP nội bộ, hỗ trợ trinh sát |
| A4 | `macAddress`, `serialNumber`, `hostname`, `instanceUuid`, `platformId` | `50:60:ab:cd:70:80`, `FCW1234L0UZ`, `leaf2.abc.inc` | Hạn chế – định danh thiết bị | Fingerprint thiết bị, giả mạo MAC, social engineering với nhà cung cấp (serial) |
| A5 | `softwareVersion`, `series`, `type` | `16.6.3`, `Cisco Catalyst 9300` | Hạn chế | Tra CVE theo phiên bản IOS-XE để khai thác |
| A6 | `cisco360view` | `https://10.10.20.22/dna/...` | Hạn chế | Lộ địa chỉ controller DNAC |
| A7 | `issueSummary`, `title`, `description` | `Network Device 10.10.20.82 Is Unreachable...` | Nội bộ | Thấp – nhưng lưu ý `issueSummary` **có nhúng IP** |
| A8 | `POLICY` (bản thân bảng phân quyền) | – | Toàn vẹn | Bị sửa đổi → mọi kiểm soát truy cập vô hiệu |

## 4. (c) Trust Boundary bị bỏ qua

| ID | Ranh giới | Mô tả |
|---|---|---|
| **TB-1** | Người dùng (role) ↔ `json_search()` | Tham số `key` và `role` đến từ phía người gọi, **không đáng tin**. Hàm phải kiểm tra kiểu, giá trị hợp lệ của role trước khi xử lý. |
| **TB-2** | `json_search()` ↔ dữ liệu API giám sát | Dữ liệu trả về từ DNAC là dữ liệu đặc quyền (chứa credential A1, IP quản trị A2). Đây là nơi dữ liệu đi từ vùng **đặc quyền cao** sang vùng **đặc quyền thấp hơn** (viewer/operator). |

**Nếu hàm không kiểm tra role trước khi trả kết quả**, TB-2 bị xoá bỏ hoàn toàn: `json_search()` trở thành một "đường ống" đưa nguyên vẹn dữ liệu từ vùng admin sang bất kỳ ai gọi được hàm. Khi đó, việc tồn tại của `policy.py` là vô nghĩa – quyền truy cập thực tế của viewer = quyền truy cập của admin. Vì hàm là điểm duy nhất tiếp xúc với dữ liệu, nó **bắt buộc** đóng vai trò *Policy Enforcement Point* (PEP); không thể giả định lớp giao diện/phía trên đã lọc thay.

## 5. (d) Phân tích mối đe doạ theo STRIDE

| ID | STRIDE | Mối đe doạ | Kịch bản cụ thể | Tài sản | Mức độ |
|---|---|---|---|---|---|
| **T1** | **I – Information Disclosure** | Viewer/operator đọc được SNMP credential | `json_search("apiKey", data, role="viewer")` trả về `["SNMP-COMMUNITY-STRING-7f3a9c"]` vì hàm không đối chiếu `POLICY` | A1 | **Nghiêm trọng** |
| **T2** | **I – Information Disclosure** | Viewer đọc được IP quản trị thiết bị | `json_search("managementIpAddress", data, role="viewer")` trả về `["10.10.20.21"]` | A2 | Cao |
| **T3** | **I – Information Disclosure** | Rò rỉ qua trường **không có trong `POLICY`** | `POLICY` chỉ định nghĩa 3 key. Nếu hàm mặc định *cho phép* với key không có trong bảng (fail-open), viewer đọc được `serialNumber`, `macAddress`, `softwareVersion`, `cisco360view`… | A3–A6 | Cao |
| **T4** | **E – Elevation of Privilege** | Vượt quyền do không kiểm tra role | Hàm bỏ qua tham số `role` (hoặc `role` có giá trị mặc định `"admin"`) → mọi người gọi đều nhận quyền admin trên dữ liệu | A1, A2 | **Nghiêm trọng** |
| **T5** | **E – Elevation of Privilege** | Bypass bằng role dị dạng | Truyền `role="Admin"`, `" admin"`, `"admin\x00"`, `role=None`, `role=["admin"]`, hoặc một object có `__eq__` luôn trả `True` (lợi dụng toán tử `in` dùng `==`) để lọt qua phép kiểm tra lỏng lẻo | A1, A2 | Cao |
| **T6** | **S – Spoofing** | Giả mạo role | `role` là tham số do người gọi tự khai báo; người dùng viewer tự truyền `role="admin"` | A1, A2 | Cao (*ngoài phạm vi hàm* – cần xác thực ở tầng trên; hàm chỉ chấp nhận tập role hợp lệ) |
| **T7** | **T – Tampering** | Sửa đổi dữ liệu / bảng `POLICY` lúc chạy | Hàm vô tình mutate `data` khi duyệt, hoặc trả về tham chiếu tới object bên trong khiến người gọi sửa được dữ liệu gốc; `POLICY` là `dict` có thể bị ghi đè (`POLICY["apiKey"].append("viewer")`) | A8, toàn bộ dữ liệu | Trung bình |
| **T8** | **R – Repudiation** | Không truy vết được ai đã đọc credential | Không có ghi log khi truy vấn trường nhạy cảm hoặc khi bị từ chối | A1, A2 | Thấp–Trung bình |
| **T9** | **D – Denial of Service** | Cạn kiệt stack do JSON lồng quá sâu | Dữ liệu (hoặc dữ liệu độc hại từ API bị giả mạo) lồng > 1000 cấp → `RecursionError` làm sập tiến trình | Tính sẵn sàng | Trung bình |
| **T10** | **I – Information Disclosure** | Lộ thông tin qua thông báo lỗi | Khi từ chối truy cập, hàm raise exception chứa giá trị trường hoặc chi tiết `POLICY` / stack trace | A1, A8 | Thấp |

### Threat trọng tâm (bắt buộc theo đề bài)

- **T1 – Information Disclosure**: Viewer lấy được `apiKey` (SNMP community string). Đây là credential cho phép truy cập trực tiếp thiết bị mạng — hậu quả là mất quyền kiểm soát hạ tầng.
- **T4 / T5 – Elevation of Privilege**: Do hàm không (hoặc kiểm tra sai cách) đối chiếu `role` với `POLICY`, một người dùng quyền thấp thực tế có được quyền đọc tương đương admin.

## 6. Biện pháp giảm thiểu (tổng quan)

| Threat | Biện pháp | Security Requirement |
|---|---|---|
| T1, T2, T4 | Đối chiếu `role` với `POLICY[key]` **trước khi** trả kết quả; không có quyền → trả `[]` | SR-01 |
| T3 | Mặc định từ chối (deny-by-default) với key không có trong `POLICY` | SR-02 |
| T5, T6 | Chỉ chấp nhận `role` là `str` thuộc tập `{"admin","operator","viewer"}`, so khớp chính xác; không có giá trị mặc định cho `role` | SR-03 |
| T7 | Không mutate `data`; `POLICY` dạng bất biến (tuple/frozenset/MappingProxyType) | SR-04 |
| T9 | Duyệt không đệ quy hoặc giới hạn độ sâu | SR-05 |
| T10 | Từ chối "im lặng" – không lộ giá trị hay chi tiết policy | SR-06 |
| T8 | Ghi log sự kiện truy cập/từ chối trường nhạy cảm (không log giá trị) | SR-07 |

Chi tiết từng yêu cầu và tiêu chí kiểm thử: xem [`SECURITY_REQUIREMENTS.md`](SECURITY_REQUIREMENTS.md).

## 7. Giả định & ngoài phạm vi

- Việc **xác thực** danh tính và gán role cho người dùng (chống T6 triệt để) do tầng ứng dụng phía trên đảm nhiệm; `json_search()` tin tưởng giá trị `role` *sau khi* nó đã được xác thực, nhưng vẫn phải kiểm tra tính hợp lệ của giá trị đó.
- `policy.py` được coi là nguồn sự thật (source of truth) về phân quyền và được quản lý qua code review.
- Kênh truyền giữa DNAC và ứng dụng (TLS) nằm ngoài phạm vi bài này.
