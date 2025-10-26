# 📸 Product Images Directory

## Hướng dẫn sử dụng hình ảnh

### 📁 Cấu trúc thư mục
```
frontend/static/images/
├── product1.jpg    # Subscription for Secure Payment Service
├── product2.jpg    # Premium Security Package
├── product3.jpg    # Data Encryption Toolkit
├── product4.jpg    # Sản phẩm tùy chỉnh
└── README.md       # File này
```

### 🔗 Cách sử dụng đường dẫn

#### **1. Trong Python (Backend)**
```python
# backend/services/order_service/main.py
MOCK_ORDERS = [
    {
        "id": "ORD-XXX",
        "description": "Product Name",
        "image": "/static/images/product1.jpg"  # ✅ ĐÚNG
    }
]
```

**❌ SAI:**
- `"image": "frontend/static/images/product1.jpg"` - Thiếu dấu `/` đầu
- `"image": "../images/product1.jpg"` - Đường dẫn tương đối sai
- `"image": "images/product1.jpg"` - Thiếu `/static/`

**✅ ĐÚNG:**
- `"image": "/static/images/product1.jpg"` - Absolute path từ root
- `"image": "/static/images/subfolder/product1.jpg"` - Có subfolder

#### **2. Trong HTML Template**
```html
<!-- orders.html -->
<img src="{{ order.image }}" alt="{{ order.description }}">
<!-- Jinja2 sẽ render thành: -->
<img src="/static/images/product1.jpg" alt="Product Name">
```

#### **3. Trong CSS**
```css
/* frontend/static/css/style.css */
.product-bg {
    background-image: url('/static/images/product1.jpg');
}
```

### 📏 Kích thước ảnh khuyến nghị

- **Kích thước:** 800x600px hoặc 1200x900px
- **Tỷ lệ:** 4:3 hoặc 16:9
- **Định dạng:** JPG (photos), PNG (graphics với transparency), WebP (modern)
- **Dung lượng:** < 500KB (nén để tối ưu tốc độ)

### 🎨 Format hỗ trợ

- ✅ `.jpg` / `.jpeg` - Tốt nhất cho photos
- ✅ `.png` - Tốt cho logos, graphics
- ✅ `.webp` - Format hiện đại, dung lượng nhỏ
- ✅ `.svg` - Vector graphics, icons
- ❌ `.gif` - Có thể dùng nhưng dung lượng lớn
- ❌ `.bmp` - Không khuyến nghị

### 🔧 Tools để tối ưu ảnh

1. **Online:**
   - TinyPNG: https://tinypng.com/
   - Squoosh: https://squoosh.app/
   - ImageOptim: https://imageoptim.com/

2. **Command Line:**
   ```bash
   # Cài đặt ImageMagick
   # Windows: https://imagemagick.org/script/download.php
   
   # Resize ảnh
   magick convert input.jpg -resize 800x600 output.jpg
   
   # Nén ảnh
   magick convert input.jpg -quality 85 output.jpg
   ```

### 📦 Cách thêm ảnh mới

1. **Download hoặc copy ảnh vào thư mục này**
   ```
   frontend/static/images/product5.jpg
   ```

2. **Cập nhật trong backend**
   ```python
   # backend/services/order_service/main.py
   {
       "id": "ORD-NEW",
       "description": "New Product",
       "image": "/static/images/product5.jpg"  # Đường dẫn mới
   }
   ```

3. **Restart server**
   ```bash
   # Ctrl+C để stop
   # Chạy lại:
   python -m uvicorn backend.gateway.main:app --reload
   ```

### 🌐 Sử dụng ảnh từ Internet (CDN)

Nếu không muốn lưu ảnh local, có thể dùng URL:

```python
# Unsplash (free, high-quality)
"image": "https://images.unsplash.com/photo-xxx?w=800&h=600&fit=crop"

# Placeholder services
"image": "https://via.placeholder.com/800x600/667eea/ffffff?text=Product"
"image": "https://picsum.photos/800/600"

# Your own CDN
"image": "https://cdn.yoursite.com/products/product1.jpg"
```

### 🔍 Troubleshooting

**Ảnh không hiển thị?**

1. **Kiểm tra đường dẫn:**
   - Đảm bảo bắt đầu với `/static/images/`
   - Kiểm tra tên file (case-sensitive trên Linux)

2. **Kiểm tra file tồn tại:**
   - Xem file có trong `frontend/static/images/` không
   - Kiểm tra quyền đọc file

3. **Kiểm tra StaticFiles mount:**
   ```python
   # backend/gateway/main.py
   app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")
   ```

4. **Kiểm tra browser console:**
   - Mở DevTools (F12)
   - Tab Network -> Filter by Images
   - Xem status code (200 = OK, 404 = Not Found)

5. **Clear cache:**
   - Ctrl + Shift + R (Windows/Linux)
   - Cmd + Shift + R (Mac)

### 📝 Ví dụ hoàn chỉnh

```python
# backend/services/order_service/main.py
MOCK_ORDERS = [
    {
        "id": "ORD-001",
        "amount": 990000,
        "currency": "VND",
        "description": "Premium Security Suite",
        "status": "PENDING",
        "image": "/static/images/security-suite.jpg"  # Local file
    },
    {
        "id": "ORD-002",
        "amount": 1590000,
        "currency": "VND",
        "description": "Enterprise Package",
        "status": "PENDING",
        "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=800"  # CDN
    }
]
```

### 🎯 Best Practices

1. ✅ **Naming convention:** `product-name-001.jpg` (lowercase, dashes)
2. ✅ **Optimize images:** Resize và compress trước khi upload
3. ✅ **Use lazy loading:** `<img loading="lazy">` (đã implement)
4. ✅ **Provide alt text:** Accessibility quan trọng
5. ✅ **Consistent sizes:** Giữ tỷ lệ giống nhau cho đồng bộ
6. ✅ **Backup:** Lưu ảnh gốc ở nơi khác để chỉnh sửa sau

---

**Last updated:** 2025-10-15
**Project:** NT219 Payment Gateway
