# Linux Hardening Scripts — Multi-OS

Repository ini berisi kumpulan script hardening Linux yang dapat digunakan secara umum oleh siapa saja untuk meningkatkan baseline keamanan server Linux.

Setiap kontrol hardening terdiri dari dua script:

- **Apply** — menerapkan konfigurasi hardening.
- **Verifikasi** — melakukan pengecekan read-only terhadap hasil konfigurasi.

---

# OS yang Didukung

Script dirancang untuk digunakan pada:

| Distribusi | Versi |
|---|---|
| Ubuntu | 22.04 LTS, 24.04 LTS |
| Debian | 12, 13 |
| Red Hat Enterprise Linux | 9.x, 10.x termasuk RHEL 10.2 |

Script mendeteksi distribusi dan versi OS sebelum menerapkan konfigurasi.

Jalankan menggunakan user dengan hak `sudo` atau sebagai `root`.

---

# ⚠️ PERINGATAN PENTING SEBELUM MENJALANKAN SCRIPT

## SSH Password Login akan dinonaktifkan secara default

Script **SSH & Session Timeout** pada kontrol nomor 3 secara default menerapkan:

```text
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
```

Artinya setelah konfigurasi diterapkan:

- login SSH menggunakan **password akan dinonaktifkan**;
- login SSH harus menggunakan **SSH key / public key authentication**;
- root hanya dapat login menggunakan SSH key;
- root tidak dapat login menggunakan password.

**PASTIKAN SSH key / public key authentication sudah berhasil digunakan sebelum menjalankan script nomor 3.**

Lakukan pengujian dari terminal/session baru terlebih dahulu:

```bash
ssh user@IP_SERVER
```

Pastikan login menggunakan key berhasil **sebelum menutup session SSH yang sedang aktif**.

Jika Anda masih ingin mempertahankan:

```text
PasswordAuthentication yes
```

maka **jangan menjalankan script nomor 3 apa adanya**, karena apply script akan mengubah nilainya menjadi `no`.

Sesuaikan policy SSH pada script terlebih dahulu, lalu pastikan konfigurasi yang efektif di salah satu atau beberapa file berikut sesuai kebutuhan:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*.conf
```

Contoh jika memang ingin tetap menggunakan password login:

```text
PasswordAuthentication yes
```

Setelah perubahan SSH, selalu validasi:

```bash
sshd -t
sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|kbdinteractiveauthentication'
```

Kemudian lakukan **duplicate SSH login test** sebelum menutup session lama.

> Untuk server production, sangat disarankan mempunyai akses console, KVM, serial console, cloud console, atau mekanisme recovery lain sebelum mengubah konfigurasi PAM dan SSH.

---

# 1. Password Policy

## Fungsi

Menerapkan baseline kebijakan password:

- Minimum panjang password: **12 karakter**
- Minimal **1 huruf besar**
- Minimal **1 huruf kecil**
- Minimal **1 angka**
- Simbol tidak diwajibkan
- Password history: **5 password terakhir**
- Default repository saat ini: password **tidak expired**
- Integrasi `pam_pwquality`
- Integrasi `pam_pwhistory`
- Dukungan `pam_faillock`

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/password_policy_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/password_policy_verifikasi_multios.sh | sudo bash
```

## Mengubah Password Expiry menjadi 90 hari

Default script saat ini menggunakan:

```text
PASS_MAX_DAYS   -1
PASS_MIN_DAYS   0
PASS_WARN_AGE   -1
```

dan existing interactive user diproses dengan:

```bash
chage -M -1 -m 0 -W -1 "${username}"
```

Artinya password **tidak pernah expired**.

Jika organisasi membutuhkan:

```text
Password Expiry : 90 days
Minimum Age     : 1 day
Warning         : 7 days
```

ubah bagian berikut di `password_policy_apply_multios.sh`:

```bash
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "90"
set_space_value "${LOGIN_DEFS}" "PASS_MIN_DAYS" "1"
set_space_value "${LOGIN_DEFS}" "PASS_WARN_AGE" "7"
```

Kemudian ubah pengaturan existing interactive user menjadi:

```bash
chage -M 90 -m 1 -W 7 "${username}"
```

Untuk expiry lebih cepat, misalnya 60 hari:

```bash
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "60"
chage -M 60 -m 1 -W 7 "${username}"
```

Verifier juga harus disesuaikan agar memeriksa nilai expiry yang sama.

> Catatan: kontrol Password Policy dan Account Lockout dipisahkan agar lebih mudah diaudit. Untuk lockout policy gunakan kontrol nomor 2 sebagai referensi utama.

---

# 2. Account Lockout / Temporary Login Ban

## Fungsi

Melindungi akun dari brute-force authentication menggunakan `pam_faillock`.

Default repository saat ini:

```text
Failure threshold          : 5 kali gagal
Failure observation window : 900 detik / 15 menit
Temporary ban              : 600 detik / 10 menit
```

Setelah 10 menit akun dapat digunakan kembali secara otomatis.

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_verify_multios.sh | sudo bash
```

## Mengubah Account Lockout menjadi 3 kali gagal

Default pada `account_lockout_apply_multios.sh`:

```bash
LOCKOUT_DENY="${LOCKOUT_DENY:-5}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
UNLOCK_TIME="${UNLOCK_TIME:-600}"
```

Jika ingin:

```text
3 kali gagal
ban 10 menit
```

ubah menjadi:

```bash
LOCKOUT_DENY="${LOCKOUT_DENY:-3}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
UNLOCK_TIME="${UNLOCK_TIME:-600}"
```

Atau jalankan tanpa mengubah file:

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_apply_multios.sh \
  | sudo env LOCKOUT_DENY=3 FAIL_INTERVAL=900 UNLOCK_TIME=600 bash
```

Untuk kebijakan:

```text
3 kali gagal
ban 30 menit
```

gunakan:

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_apply_multios.sh \
  | sudo env LOCKOUT_DENY=3 FAIL_INTERVAL=900 UNLOCK_TIME=1800 bash
```

Jalankan verifier dengan nilai yang sama:

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_verify_multios.sh \
  | sudo env LOCKOUT_DENY=3 FAIL_INTERVAL=900 UNLOCK_TIME=600 bash
```

---

# 3. SSH & Session Timeout

## Fungsi

Mengamankan konfigurasi SSH serta idle timeout untuk interactive shell.

Default policy:

```text
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
ClientAliveInterval 300
ClientAliveCountMax 3
TMOUT 900 seconds
```

`PermitRootLogin prohibit-password` berarti root masih diperbolehkan login menggunakan SSH key, tetapi tidak menggunakan password.

Script mengubah:

```text
/etc/ssh/sshd_config
/etc/profile.d/99-session-timeout.sh
```

Script **tidak membuat file baru di `/etc/ssh/sshd_config.d/`**.

Namun effective configuration OpenSSH tetap dapat dipengaruhi oleh file yang sudah ada di:

```text
/etc/ssh/sshd_config.d/*.conf
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/session_timeout_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/session_timeout_verify_multios.sh | sudo bash
```

## Jika ingin tetap menggunakan password login

Default script akan mengubah:

```text
PasswordAuthentication no
```

Jika password login harus tetap digunakan, ubah policy di apply script menjadi:

```text
PasswordAuthentication yes
```

dan pastikan effective configuration pada:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/*.conf
```

tidak menimpa nilai tersebut.

Periksa dengan:

```bash
sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|kbdinteractiveauthentication'
```

## Mengubah Interactive Idle Timeout

Default:

```text
SESSION_TIMEOUT=900
```

atau 15 menit.

Contoh 10 menit:

```text
SESSION_TIMEOUT=600
```

---

# 4. Auditd Hardening

## Fungsi

Mengaktifkan dan menerapkan audit rule untuk mencatat perubahan keamanan penting pada sistem.

Rule utama meliputi:

- perubahan waktu
- perubahan identity/account
- hostname dan network configuration
- AppArmor pada Ubuntu/Debian
- SELinux pada RHEL
- login record
- session record
- permission/ownership change
- unauthorized file access
- delete/rename
- sudo configuration
- privileged command execution

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/auditd_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/auditd_verifikasi_multios.sh | sudo bash
```

Managed rules saat ini disimpan pada:

```text
/etc/audit/rules.d/50-dbalance-hardening.rules
```

Nama file tersebut dipertahankan untuk kompatibilitas repository, tetapi rule di dalamnya dapat digunakan pada server Linux umum.

Verifier memastikan:

```text
auditd active
auditd enabled
kernel auditing enabled
lost audit events = 0
```

---

# 5. /tmp Hardening

## Fungsi

Membuat `/tmp` sebagai dedicated `tmpfs` dengan:

```text
nodev
nosuid
noexec
mode=1777
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/tmp_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/tmp_hardening_verifikasi_multios.sh | sudo bash
```

Managed unit:

```text
/etc/systemd/system/tmp.mount
```

Jika `/tmp` sedang digunakan oleh proses aktif, script dapat menunda live activation untuk menghindari gangguan service. Dalam kondisi tersebut reboot pada maintenance window mungkin diperlukan.

---

# 6. /dev/shm Hardening

## Fungsi

Mengamankan shared memory `/dev/shm`.

Policy:

```text
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec,mode=1777 0 0
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/shm_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/shm_hardening_verifikasi_multios.sh | sudo bash
```

Script memastikan:

```text
filesystem = tmpfs
nodev
nosuid
noexec
owner = root:root
permission = 1777
```

Konfigurasi persistent disimpan melalui `/etc/fstab`.

---

# 7. /var/tmp Hardening

## Fungsi

Membuat `/var/tmp` sebagai bind mount dari `/tmp` dengan:

```text
rw
nodev
nosuid
noexec
bind
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/var_tmp_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/var_tmp_hardening_verifikasi_multios.sh | sudo bash
```

Entry `/etc/fstab`:

```text
/tmp /var/tmp none rw,nodev,nosuid,noexec,bind 0 0
```

> **Perhatian:** apabila `/tmp` menggunakan `tmpfs`, maka `/var/tmp` menggunakan backing storage yang sama dan menjadi **non-persistent setelah reboot**. Pertimbangkan kebutuhan aplikasi sebelum menerapkan kontrol ini.

---

# 8. Sticky Bit Hardening

## Fungsi

Memastikan world-writable directory pada filesystem lokal mempunyai sticky bit.

Contoh:

```text
/tmp
/var/tmp
/dev/shm
/run/lock
```

Sticky bit mencegah user biasa menghapus file milik user lain pada shared directory.

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/sticky_bit_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/sticky_bit_hardening_verifikasi_multios.sh | sudo bash
```

Jika output apply menunjukkan:

```text
Directories fixed: 0
```

itu normal. Artinya tidak ditemukan world-writable directory yang membutuhkan perbaikan sticky bit.

---

# 9. Login Banner Hardening — OPSIONAL

## Status

**Kontrol ini opsional dan tidak bersifat generic.**

Script saat ini memasang banner milik:

```text
DATACOMM / DCloud
```

Karena itu **jangan menjalankan script ini pada server organisasi lain** kecuali Anda memang berhak menggunakan banner tersebut atau sudah mengganti kontennya dengan legal notice milik organisasi Anda sendiri.

## Fungsi

Mengganti `/etc/issue` dengan warning banner DATACOMM/DCloud dan menghindari disclosure informasi distro/versi OS pada local login banner.

Default banner mengandung:

```text
USAGE WARNING
DATACOMM PRIVATE PROPRIETARY
consent to monitoring
unauthorized-use warning
```

Policy file:

```text
owner      : root:root
permission : 0644
```

### Menjalankan Apply + Verifikasi — hanya untuk lingkungan DATACOMM/DCloud

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/login_banner_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/login_banner_verifikasi_multios.sh | sudo bash
```

Untuk penggunaan umum, edit terlebih dahulu isi banner pada:

```text
login_banner_hardening_multios.sh
```

dan sesuaikan verifier jika wording organisasi Anda berbeda.

Script hanya mengelola:

```text
/etc/issue
```

dan tidak mengubah konfigurasi SSH.

---

# 10. Chrony / NTP Hardening

## Fungsi

Menggunakan Chrony sebagai service sinkronisasi waktu dan mengarahkannya ke Indonesia NTP Pool.

NTP server:

```text
0.id.pool.ntp.org
1.id.pool.ntp.org
2.id.pool.ntp.org
3.id.pool.ntp.org
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/chrony_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/chrony_hardening_verifikasi_multios.sh | sudo bash
```

Perbedaan otomatis:

```text
Ubuntu / Debian
Configuration : /etc/chrony/chrony.conf
Service       : chrony.service

RHEL
Configuration : /etc/chrony.conf
Service       : chronyd.service
```

Verifier memeriksa:

- package Chrony ter-install
- service active dan enabled
- 4 server NTP Indonesia terkonfigurasi
- syntax konfigurasi valid
- source NTP tersedia
- selected source tersedia
- stratum valid
- `Leap status = Normal`
- system clock synchronized
- `systemd-timesyncd` tidak aktif
- tidak ada konflik dengan legacy `ntpd`

Sesaat setelah Chrony direstart, source dapat terlihat:

```text
^?
```

Tunggu sekitar 30–90 detik kemudian periksa kembali.

Kondisi normal biasanya:

```text
^*  selected / current best source
^+  valid combined source
^-  valid but not selected
```

---

# Recommended Execution Order

Untuk server baru, urutan yang disarankan:

```text
1. Password Policy
2. Account Lockout
3. SSH & Session Timeout
4. Auditd
5. /tmp
6. /dev/shm
7. /var/tmp
8. Sticky Bit
9. Login Banner — OPTIONAL
10. Chrony / NTP
```

Setiap **apply script sebaiknya langsung diikuti verification script** sebelum melanjutkan ke kontrol berikutnya.

Login Banner nomor 9 dapat dilewati sepenuhnya apabila server bukan milik DATACOMM/DCloud atau organisasi Anda menggunakan banner sendiri.

---

# Pre-Hardening Checklist

Sebelum menjalankan hardening pada production:

1. Pastikan akses console/recovery tersedia.
2. Buat snapshot atau backup VM.
3. Pastikan SSH key/public-key login sudah berhasil.
4. Pertahankan satu SSH session aktif saat mengubah PAM/SSH.
5. Uji script terlebih dahulu pada staging/test VM dengan OS yang sama.
6. Jalankan verification script setelah setiap apply.
7. Lakukan duplicate SSH login test setelah perubahan PAM/SSH.
8. Jangan reboot sebelum memastikan konfigurasi filesystem dan service valid.
9. Periksa kebutuhan aplikasi terhadap `/tmp`, `/dev/shm`, dan `/var/tmp`.
10. Sesuaikan policy organisasi sebelum deployment massal.

---

# Default Security Policy Summary

| Control | Default |
|---|---|
| Password minimum length | 12 |
| Uppercase | Required |
| Lowercase | Required |
| Digit | Required |
| Special character | Not required |
| Password history | Last 5 |
| Password expiry | Never |
| Login failure threshold | 5 |
| Temporary ban | 10 minutes |
| Failure observation window | 15 minutes |
| Interactive idle timeout | 15 minutes |
| SSH password authentication | **Disabled** |
| Root SSH login | SSH key only |
| `/tmp` | tmpfs + nodev,nosuid,noexec |
| `/dev/shm` | tmpfs + nodev,nosuid,noexec |
| `/var/tmp` | bind from `/tmp` + nodev,nosuid,noexec |
| Sticky bit | Enforced on world-writable directories |
| Login Banner | **Optional — DATACOMM/DCloud-specific by default** |
| NTP | Indonesia NTP Pool |

---

# Common Customization Examples

## Password Expiry 90 Days

```text
PASS_MAX_DAYS = 90
PASS_MIN_DAYS = 1
PASS_WARN_AGE = 7
```

Existing users:

```bash
chage -M 90 -m 1 -W 7 USERNAME
```

## Account Lockout 3 Attempts

```text
deny = 3
fail_interval = 900
unlock_time = 600
```

## Keep SSH Password Login Enabled

Ubah policy nomor 3 agar:

```text
PasswordAuthentication yes
```

kemudian pastikan effective configuration:

```bash
sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|kbdinteractiveauthentication'
```

---

# Repository

```text
https://github.com/ica4me/linux-hardening-scripts
```

## Disclaimer

Script ini disediakan sebagai baseline hardening umum. Setiap environment dapat mempunyai kebutuhan autentikasi, aplikasi, filesystem, compliance, dan availability yang berbeda.

Selalu review script, lakukan backup, uji pada staging, dan sesuaikan dengan policy organisasi sebelum diterapkan pada production.
