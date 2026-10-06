# Linux Hardening Scripts — DBalance Multi-OS

Repository ini berisi kumpulan script hardening Linux untuk kebutuhan server DBalance.  
Setiap kontrol hardening terdiri dari dua script:

- **Apply** — menerapkan konfigurasi hardening.
- **Verifikasi** — melakukan pengecekan read-only terhadap hasil konfigurasi.

## OS yang Didukung

Script dirancang untuk digunakan pada:

| Distribusi | Versi |
|---|---|
| Ubuntu | 22.04 LTS, 24.04 LTS |
| Debian | 12, 13 |
| Red Hat Enterprise Linux | 9.x, 10.x termasuk RHEL 10.2 |

> Jalankan seluruh script menggunakan user yang mempunyai hak `sudo` atau sebagai `root`.

---

# 1. Password Policy

## Fungsi

Menerapkan kebijakan password, meliputi:

- Minimum panjang password: **12 karakter**
- Minimal **1 huruf besar**
- Minimal **1 huruf kecil**
- Minimal **1 angka**
- Simbol tidak diwajibkan
- Password history: **5 password terakhir**
- Default repository saat ini: password **tidak expired**
- Temporary login ban menggunakan `pam_faillock`

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/password_policy_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/password_policy_verifikasi_multios.sh | sudo bash
```

## Jika ingin menerapkan Password Expiry 90 hari

Default script saat ini menggunakan:

```bash
PASS_MAX_DAYS   -1
PASS_MIN_DAYS   0
PASS_WARN_AGE   -1
```

dan user existing diproses menggunakan:

```bash
chage -M -1 -m 0 -W -1 USERNAME
```

Artinya password tidak pernah expired.

Jika kebijakan yang diinginkan adalah:

- Maximum password age: **90 hari**
- Minimum password age: **1 hari**
- Warning sebelum expired: **7 hari**

ubah bagian pada `password_policy_apply_multios.sh` menjadi:

```bash
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "90"
set_space_value "${LOGIN_DEFS}" "PASS_MIN_DAYS" "1"
set_space_value "${LOGIN_DEFS}" "PASS_WARN_AGE" "7"
```

dan ubah bagian `chage` untuk existing interactive users menjadi:

```bash
chage -M 90 -m 1 -W 7 "${username}"
```

Jika ingin masa berlaku password **lebih cepat dari 90 hari**, cukup ganti nilai `90`. Contoh 60 hari:

```bash
set_space_value "${LOGIN_DEFS}" "PASS_MAX_DAYS" "60"
chage -M 60 -m 1 -W 7 "${username}"
```

Verifier juga harus disesuaikan agar mengecek nilai expiry yang sama.

> Catatan: script Password Policy juga memiliki konfigurasi `pam_faillock`. Untuk pengelolaan lockout yang lebih jelas dan terpisah, gunakan kontrol nomor 2 sebagai referensi utama Account Lockout.

---

# 2. Account Lockout / Temporary Login Ban

## Fungsi

Melindungi akun dari brute-force login menggunakan `pam_faillock`.

Default repository saat ini:

```text
5 failed attempts
Failure observation window: 900 seconds
Temporary ban: 600 seconds / 10 minutes
```

Setelah 10 menit akun dapat digunakan kembali secara otomatis.

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_verify_multios.sh | sudo bash
```

## Jika ingin Account Lockout 3 kali gagal

Pada `account_lockout_apply_multios.sh`, default-nya:

```bash
LOCKOUT_DENY="${LOCKOUT_DENY:-5}"
FAIL_INTERVAL="${FAIL_INTERVAL:-900}"
UNLOCK_TIME="${UNLOCK_TIME:-600}"
```

Untuk menjadikan threshold **3 kali gagal**, ubah menjadi:

```bash
LOCKOUT_DENY="${LOCKOUT_DENY:-3}"
```

atau tanpa mengubah file:

```bash
LOCKOUT_DENY=3 curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/account_lockout_apply_multios.sh | sudo -E bash
```

Untuk kebijakan:

```text
3 kali gagal
ban 10 menit
```

gunakan:

```bash
LOCKOUT_DENY=3
UNLOCK_TIME=600
```

Untuk kebijakan lama:

```text
3 kali gagal
ban 30 menit
```

gunakan:

```bash
LOCKOUT_DENY=3
UNLOCK_TIME=1800
```

Verifier harus menggunakan threshold dan durasi yang sama.

---

# 3. SSH & Session Timeout

## Fungsi

Mengamankan konfigurasi SSH dan idle interactive shell.

Policy:

```text
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
ClientAliveInterval 300
ClientAliveCountMax 3
TMOUT 900 seconds
```

`PermitRootLogin prohibit-password` berarti root masih dapat login menggunakan SSH key, tetapi tidak menggunakan password.

Script hanya mengubah:

```text
/etc/ssh/sshd_config
/etc/profile.d/99-session-timeout.sh
```

Script **tidak membuat atau mengubah file baru di `/etc/ssh/sshd_config.d/`**.

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/session_timeout_apply_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/session_timeout_verify_multios.sh | sudo bash
```

Jika ingin mengubah idle timeout, misalnya menjadi 10 menit:

```text
SESSION_TIMEOUT=600
```

Default saat ini:

```text
SESSION_TIMEOUT=900
```

---

# 4. Auditd Hardening

## Fungsi

Mengaktifkan dan menerapkan rule audit untuk mencatat perubahan keamanan penting.

Rule utama meliputi:

- perubahan waktu
- perubahan identity/account
- hostname dan network configuration
- AppArmor pada Ubuntu/Debian
- SELinux pada RHEL
- login record
- session record
- permission/ownership change
- unauthorized access
- delete/rename
- sudo configuration
- privileged command execution

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/auditd_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/auditd_verifikasi_multios.sh | sudo bash
```

Managed rules disimpan pada:

```text
/etc/audit/rules.d/50-dbalance-hardening.rules
```

Verifier juga memastikan:

```text
auditd active
auditd enabled
kernel auditing enabled
lost audit events = 0
```

---

# 5. /tmp Hardening

## Fungsi

Membuat `/tmp` sebagai dedicated `tmpfs` dengan opsi keamanan:

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

Jika `/tmp` sedang digunakan oleh proses aktif, script dapat menunda aktivasi live dan mengaktifkannya pada reboot berikutnya untuk menghindari gangguan service.

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

- filesystem tetap `tmpfs`
- `nodev`
- `nosuid`
- `noexec`
- owner `root:root`
- permission `1777`

Konfigurasi persistent disimpan melalui `/etc/fstab`.

---

# 7. /var/tmp Hardening

## Fungsi

Membuat `/var/tmp` sebagai bind mount dari `/tmp`, kemudian menerapkan:

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

Entry fstab:

```text
/tmp /var/tmp none rw,nodev,nosuid,noexec,bind 0 0
```

> Perhatian: apabila `/tmp` menggunakan `tmpfs`, maka `/var/tmp` juga menggunakan backing storage yang sama dan menjadi **non-persistent setelah reboot**. Ini merupakan konsekuensi dari desain bind mount ini.

---

# 8. Sticky Bit Hardening

## Fungsi

Memastikan seluruh world-writable directory pada filesystem lokal mempunyai sticky bit.

Contoh direktori penting:

```text
/tmp
/var/tmp
/dev/shm
/run/lock
```

Sticky bit mencegah user menghapus file milik user lain pada shared directory.

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/sticky_bit_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/sticky_bit_hardening_verifikasi_multios.sh | sudo bash
```

Jika output apply menunjukkan:

```text
Directories fixed: 0
```

itu normal dan berarti seluruh directory yang ditemukan sudah mempunyai sticky bit.

---

# 9. Login Banner Hardening

## Fungsi

Mengganti `/etc/issue` dengan warning banner DATACOMM dan mencegah informasi distro/versi OS ditampilkan pada local login banner.

Policy file:

```text
owner      : root:root
permission : 0644
```

Banner berisi:

```text
USAGE WARNING
DATACOMM PRIVATE PROPRIETARY
consent to monitoring
unauthorized-use warning
```

### Menjalankan Apply + Verifikasi

```bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/login_banner_hardening_multios.sh | sudo bash
curl -sL https://raw.githubusercontent.com/ica4me/linux-hardening-scripts/main/login_banner_verifikasi_multios.sh | sudo bash
```

Script hanya mengelola:

```text
/etc/issue
```

dan tidak mengubah `sshd_config`.

---

# 10. Chrony / NTP Hardening

## Fungsi

Menggunakan Chrony sebagai service sinkronisasi waktu dan menggunakan Indonesia NTP Pool.

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

Perbedaan otomatis berdasarkan OS:

```text
Ubuntu/Debian
Configuration : /etc/chrony/chrony.conf
Service       : chrony.service

RHEL
Configuration : /etc/chrony.conf
Service       : chronyd.service
```

Verifier memeriksa:

- Chrony ter-install
- service active dan enabled
- empat server Indonesia terkonfigurasi
- syntax konfigurasi valid
- source NTP tersedia
- selected source tersedia
- stratum valid
- Leap status `Normal`
- system clock synchronized
- `systemd-timesyncd` tidak aktif
- tidak ada konflik dengan legacy `ntpd`

Sesaat setelah restart Chrony, source dapat terlihat sebagai:

```text
^?
```

Tunggu sekitar 30–90 detik dan cek kembali. Kondisi normal biasanya akan mempunyai:

```text
^*  selected source
^+  usable source
^-  valid but not selected
```

---

# Recommended Execution Order

Untuk deployment server baru, urutan yang disarankan:

```text
1. Password Policy
2. Account Lockout
3. SSH & Session Timeout
4. Auditd
5. /tmp
6. /dev/shm
7. /var/tmp
8. Sticky Bit
9. Login Banner
10. Chrony / NTP
```

Setiap **apply script sebaiknya langsung diikuti verification script** sebelum melanjutkan ke kontrol berikutnya.

---

# Pre-Hardening Recommendation

Sebelum menjalankan script pada production:

1. Pastikan akses console tersedia.
2. Buat snapshot atau backup VM.
3. Pertahankan satu SSH session aktif selama hardening SSH/PAM.
4. Uji terlebih dahulu pada staging/test VM dengan OS yang sama.
5. Jalankan verification script setelah setiap apply.
6. Jika melakukan perubahan PAM/SSH, lakukan duplicate SSH login sebelum menutup session existing.

---

# Custom Policy Summary

Default repository saat ini:

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
| SSH password authentication | Disabled |
| Root SSH login | SSH key only |
| `/tmp` | tmpfs + nodev,nosuid,noexec |
| `/dev/shm` | tmpfs + nodev,nosuid,noexec |
| `/var/tmp` | bind from `/tmp` + nodev,nosuid,noexec |
| NTP | Indonesia NTP Pool |

Untuk policy organisasi yang membutuhkan:

```text
Password Expiry : 90 days
Account Lockout : 3 failed attempts
```

ikuti bagian **1. Password Policy** dan **2. Account Lockout** pada README ini sebelum deployment ke production.

---

## Repository

```text
https://github.com/ica4me/linux-hardening-scripts
```
