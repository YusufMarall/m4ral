# m4ral — Güvenlik Araçları Koleksiyonu

Bu depo, yetkili güvenlik testleri ve tehdit istihbaratı için geliştirilmiş iki bağımsız projeyi barındırır:

| Proje | Klasör | Amaç | Teknoloji |
| --- | --- | --- | --- |
| **Auth Pentest Aracı** | [`auth_pentest_tool/`](auth_pentest_tool/) | Otonom kimlik doğrulama (auth) odaklı sızma testi aracı | Python 3 · Kali Linux · Docker |
| **OpenTIP** | [`opentip/`](opentip/) | Açık kaynak tehdit istihbaratı platformu | Python 3.13 · Streamlit · SQLite · Docker |

---

## 1. auth_pentest_tool — Otonom Auth Pentest Aracı

TSE A sınıfı sızma testi akışına uygun, aşamalı (önce pasif, sonra onaylı aktif) çalışan tek dosyalık (standalone) bir CLI aracıdır. Kali Linux tabanlı bir Docker imajı ile tüm bağımlılıklarıyla birlikte gelir.

### Özellikler

- **Pasif Recon:** WHOIS, DNS kayıtları, alt alan adı keşfi (crt.sh / subfinder), Wayback Machine, Google dork üretimi, sosyal medya bağlantıları, e-posta/breach kontrolü.
- **Aktif Recon:** Port taraması, teknoloji parmak izi, HTTP güvenlik başlıkları, SSL/TLS değerlendirmesi (testssl + socket), CORS kontrolü, dizin/dosya keşfi.
- **Port / Servis Zafiyet Taraması:** `nmap -sV -sC` + FTP (anonim), SMB (MS17-010 / SMBv1 / imzalama / anonim paylaşım), SSH (ssh-audit), RDP (NLA), MySQL/MSSQL/PostgreSQL (boş parola), Redis (parolasız), Elasticsearch, NFS, SNMP (public community) kontrolleri.
- **Auth Testleri:** Login formu tespiti, kullanıcı adı enumerasyonu, varsayılan/zayıf parola denemesi, CSRF, cookie güvenliği (Secure/HttpOnly/SameSite), rate limit, hesap kilitleme politikası.
- **JWT / IDOR / Yetki Yükseltme:** Oturum cookie'si veya Bearer token ile **authenticated mod**; `alg=none` bypass, payload manipülasyonu ile IDOR ve rol/yetki yükseltme testleri.
- **WAF Bypass:** Origin IP tespiti (6 farklı kaynak) + `Host` header ile CDN atlama, `cf_clearance` cookie enjeksiyonu, özel header, proxy (Burp/ZAP), insan taklidi gecikme, User-Agent rotasyonu, üstel geri çekilme + retry, `--auto-bypass` (otomatik).
- **Raporlama:** HTML (görsel), TXT (metin) ve JSON çıktı.

### Hızlı Başlangıç (Docker — önerilen)

```bash
# İmajı derle (Kali tabanlı; nmap, subfinder, smbclient, testssl vb. dahil)
docker build -f auth_pentest_tool/Dockerfile.auth_tool -t auth-pentest-tool:v1 auth_pentest_tool

# Tam tarama (pasif + aktif + auth)
docker run -it --rm --network host \
  -v "$PWD/results:/app/results" \
  auth-pentest-tool:v1 \
  -t "https://HEDEF.com" --full-autorun --aggressive-auth
```

### Hızlı Başlangıç (Yerel Python)

```bash
cd auth_pentest_tool
pip install -r requirements_auth_tool.txt
python auth_pentest_tool.py -t "https://HEDEF.com" --full-autorun
```

### Sık Kullanılan Komutlar

```bash
# Port / servis zafiyet taraması dahil
python auth_pentest_tool.py -t "https://HEDEF.com" --full-autorun --port-scan

# WAF arkasındaki hedef için otomatik bypass + insan taklidi
python auth_pentest_tool.py -t "https://HEDEF.com" --full-autorun --auto-bypass --human-mode --rotate-ua

# Oturum cookie'si ile authenticated JWT/IDOR testleri
python auth_pentest_tool.py -t "https://HEDEF.com/hesabim" --full-autorun \
  --auth-cookie "session=eyJhbGciOi..." --aggressive-auth

# Belirli portları tara
python auth_pentest_tool.py -t "HEDEF.com" --full-autorun --port-scan --ports 21,22,445,3306,3389
```

> Tam argüman listesi: `python auth_pentest_tool.py --help`

---

## 2. opentip — Open Threat Intelligence Platform

Açık kaynak istihbarat kaynaklarını ve **yetkili** sızıntı izleme kaynaklarını tek bir analiz sürecinde birleştiren Streamlit tabanlı platform. Üç modül içerir: **IOC Intelligence**, **Breach Intelligence** ve **Dark Web Monitoring**.

Detaylı dokümantasyon: [`opentip/README.md`](opentip/README.md)

```bash
cd opentip
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
streamlit run app.py
```

Arayüz: <http://localhost:8501> · Docker: `docker compose up -d --build`

---

## ⚠️ Sorumluluk ve Etik Kullanım

Bu depodaki araçlar **yalnızca açık yazılı izin (sözleşme/kapsam) alınmış hedeflerde ve yetkili güvenlik testlerinde** kullanılmak üzere geliştirilmiştir. İzinsiz sistemlere yönelik kullanım yasa dışıdır. Kullanıcı, kullandığı tüm kaynak ve hedeflerin koşullarına ve yürürlükteki mevzuata uymakla yükümlüdür.

## Gizli Bilgi Politikası

- `.env` dosyaları ve API anahtarları **asla** sürüm kontrolüne eklenmez (bkz. `.gitignore`).
- Tarama çıktıları (`results/`), veritabanları ve üretilen raporlar depoda tutulmaz.
