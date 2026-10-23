# m4ral — Güvenlik Araçları Koleksiyonu

Bu depo, yetkili güvenlik testleri ve tehdit istihbaratı için geliştirilmiş iki bağımsız projeyi barındırır:

| Proje | Klasör | Amaç | Teknoloji |
| --- | --- | --- | --- |
| **Auth Pentest Aracı** | [`auth_pentest_tool/`](auth_pentest_tool/) | Otonom kimlik doğrulama (auth) odaklı sızma testi aracı | Python 3 · Kali Linux · Docker |
| **OpenTIP** | [`opentip/`](opentip/) | Açık kaynak tehdit istihbaratı platformu | Python 3.13 · Streamlit · SQLite · Docker |

---

## Kullanılan Teknolojiler

### auth_pentest_tool

| Katman | Teknoloji |
| --- | --- |
| Dil | Python 3 |
| Çalışma ortamı | Kali Linux Rolling (Docker) veya yerel Python 3 |
| HTTP istemci | `requests`, `cloudscraper`, `requests-toolbelt` |
| HTML ayrıştırma | `beautifulsoup4` (bs4), `lxml` |
| Terminal çıktısı | `colorama` |
| Gömülü araçlar (Docker imajı) | `nmap`, `whois`, `dig`/`dnsutils`, `netcat`, `curl`/`wget`, `subfinder`, `amass`, `theHarvester`, `CeWL`, `gobuster`, `ffuf`, `nikto`, `testssl.sh` |
| Wordlist | SecLists + `wordlists` (rockyou.txt) |
| Servis denetim araçları | `ssh-audit`, `smbclient`, `nfs-common` (showmount) |
| Konteyner | Docker — `kalilinux/kali-rolling` tabanlı, `ENTRYPOINT` ile CLI |
| Raporlama | HTML / TXT / JSON (saf Python, harici motor yok) |

### opentip

| Katman | Teknoloji |
| --- | --- |
| Dil | Python 3.13 |
| Web arayüz | Streamlit 1.39 |
| Ayarlar / veri doğrulama | Pydantic 2 + pydantic-settings |
| HTTP istemci | `requests` |
| Zamanlayıcı (periyodik kontrol) | APScheduler |
| Rapor şablonları | Jinja2 |
| Ortam değişkenleri | python-dotenv (`.env`) |
| Veritabanı | SQLite |
| Test | pytest |
| Konteyner | Docker · Docker Compose (`python:3.13-slim`, non-root kullanıcı, healthcheck) |

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

## API Anahtarları ve Ortam Değişkenleri

### auth_pentest_tool

Araç **hiçbir API anahtarı veya `.env` dosyası gerektirmez**. Yalnızca hedefe doğrudan HTTP istekleri ve herkese açık / anahtarsız servisleri (dns.google, crt.sh, RDAP, Wayback Machine vb.) kullanır.

### opentip

`.env.example` dosyasını `.env` olarak kopyalayıp doldurun. **`.env` asla sürüm kontrolüne eklenmez** (bkz. `.gitignore`). Kaynaklar varsayılan olarak kapalıdır; yalnızca etkinleştirdiğiniz kaynakların anahtarları gerekir.

#### Veri kaynağı anahtarları

| Değişken(ler) | Kaynak | Zorunluluk | Nereden alınır |
| --- | --- | --- | --- |
| `OTX_API_KEY` | AlienVault OTX | Opsiyonel (anahtarsız da kısıtlı çalışır) | https://otx.alienvault.com |
| `THREATFOX_API_KEY` | abuse.ch ThreatFox | `THREATFOX_ENABLED=true` ise gerekli | https://threatfox.abuse.ch/api/ |
| `MISP_URL`, `MISP_API_KEY` | MISP örneği | Yalnızca yetkili erişim | Kendi MISP kurulumunuz |
| `XPOSEDORNOT_API_KEY` | XposedOrNot | Public sorgu anahtarsız; doğrulanmış domain izleme için gerekli | https://xposedornot.com |
| `BREACH_FEED_URL`, `BREACH_FEED_API_KEY` | İzinli breach feed | Sağlayıcı sözleşmesi | Tedarikçi (yapılandırılmış JSON akışı) |
| `DARKWEB_SOURCE_URL`, `DARKWEB_SOURCE_API_KEY` | İzinli dark web kaynağı | Sağlayıcı sözleşmesi | Tedarikçi |
| `DEEPDARKCTI_BASE_URL` | deepdarkCTI (GitHub) | **Anahtar gerekmez** | https://github.com/fastfire/deepdarkCTI |

#### Genel yapılandırma

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `APP_NAME` | `OpenTIP` | Uygulama adı |
| `ENVIRONMENT` | `development` | Çalışma ortamı |
| `LOG_LEVEL` | `INFO` | Log seviyesi |
| `DATABASE_PATH` | `./data/opentip.db` | SQLite veritabanı yolu |
| `REPORT_OUTPUT_DIR` | `./reports_output` | Rapor çıktı klasörü |
| `HTTP_TIMEOUT` | `15` | Tüm adaptörler için HTTP zaman aşımı (sn) |
| `HTTP_MAX_RETRIES` | `3` | HTTP yeniden deneme sayısı |
| `HTTP_BACKOFF_SECONDS` | `1.5` | Denemeler arası bekleme (sn) |
| `REQUESTS_PER_MINUTE` | `30` | Dakikalık istek hız limiti |
| `SCHEDULER_ENABLED` | `false` | Periyodik kontrol (MVP'de kapalı) |
| `DEFAULT_CHECK_INTERVAL_MINUTES` | `60` | Kontrol aralığı (dk) |

> Tüm anahtarlar yalnızca `.env` üzerinden okunur ve **imaja gömülmez** (`docker-compose.yml` `env_file` kullanır). Repoda hiçbir gerçek anahtar bulunmaz; yalnızca boş değerli `.env.example` yer alır.

---

## ⚠️ Sorumluluk ve Etik Kullanım

Bu depodaki araçlar **yalnızca açık yazılı izin (sözleşme/kapsam) alınmış hedeflerde ve yetkili güvenlik testlerinde** kullanılmak üzere geliştirilmiştir. İzinsiz sistemlere yönelik kullanım yasa dışıdır. Kullanıcı, kullandığı tüm kaynak ve hedeflerin koşullarına ve yürürlükteki mevzuata uymakla yükümlüdür.

## Gizli Bilgi Politikası

- `.env` dosyaları ve API anahtarları **asla** sürüm kontrolüne eklenmez (bkz. `.gitignore`).
- Tarama çıktıları (`results/`), veritabanları ve üretilen raporlar depoda tutulmaz.
