# OpenTIP — Open Threat Intelligence Platform

Açık kaynak istihbarat kaynaklarını ve **yetkili** sızıntı izleme kaynaklarını tek bir analiz
sürecinde birleştiren platform. Üç modül içerir:

1. **IOC Intelligence** — IP, domain, URL ve dosya hash değerlerinin tehdit istihbaratı
   kaynaklarında (AlienVault OTX, ThreatFox, MISP) araştırılması.
2. **Breach Intelligence** — Kurumla ilişkili sızıntı kayıtlarının ve ifşa iddialarının
   kaydedilmesi, kanıt ve doğrulama durumu ile birlikte değerlendirilmesi.
3. **Dark Web Monitoring** — Yalnızca **erişim izni bulunan, yapılandırılmış** kaynakların
   zamanlanmış olarak kontrol edilmesi ve yeni/değişen bulgular için uyarı üretilmesi.

- **Arayüz:** Streamlit · **Veritabanı:** SQLite · **Dağıtım:** Docker · **Dil:** Python 3.13

---

## 1. Kapsam ve etik kısıtlar

Bu proje aşağıdaki işlemleri **yapmaz** ve yapmayacak şekilde tasarlanmıştır:

- Çalıntı veri satın almak veya satıcılarla iletişim kurmak.
- Sızdırılmış kimlik bilgilerini doğrulamak için kullanmak.
- Yetkisiz erişim, aktif tarama veya kimlik doğrulama denemesi yapmak.
- "Tüm Dark Web tarandı" gibi doğrulanamayan bir kapsam iddiası üretmek.
- Doğrulanmamış bir iddiayı **ihlal** olarak sunmak.

Doğrulama durumu (`VerificationStatus`) ile risk seviyesi (`RiskLevel`) birbirinden **bağımsız**
tutulur. Bir iddia yüksek riskli olabilir ancak hâlâ doğrulanmamış olabilir; bu durum arayüzde ve
raporlarda açıkça ayrı gösterilir.

Sızdırılmış veri **gövdesi saklanmaz**. Kayıtlarda yalnızca kaynak referansı, tarih, varlık eşleşmesi
ve kanıt özeti tutulur. Raporlar `scrub()` ile temizlenir ve API anahtarları hiçbir koşulda rapora
veya kaynak koduna girmez; anahtarlar yalnızca ortam değişkeni adı (`api_key_env`) olarak veritabanında tutulur.

---

## 2. Gereksinimler

- Python **3.13+** (veya Docker)
- pip
- İnternet erişimi (kaynak adaptörleri için; opsiyonel, testler ağ erişimi gerektirmez)

---

## 3. Yerel kurulum

```bash
cd opentip

# Sanal ortam
python -m venv .venv
.venv\Scripts\activate        # Windows (PowerShell)
# source .venv/bin/activate   # Linux / macOS

# Bağımlılıklar
pip install -r requirements.txt

# Yapılandırma
copy .env.example .env        # Windows
# cp .env.example .env        # Linux / macOS
```

### Ortam değişkenleri (`.env`)

`.env` **asla** sürüm kontrolüne eklenmez (`.gitignore` içinde). `.env.example` şablonunu kopyalayıp
yalnızca kullanacağınız kaynakları doldurun.

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `APP_NAME` | `OpenTIP` | Uygulama adı |
| `ENVIRONMENT` | `development` | Çalışma ortamı |
| `LOG_LEVEL` | `INFO` | Günlük seviyesi |
| `DATABASE_PATH` | `./data/opentip.db` | SQLite veritabanı yolu |
| `REPORT_OUTPUT_DIR` | `./reports_output` | JSON/HTML rapor çıktı dizini |
| `HTTP_TIMEOUT` | `15` | Adaptör istek zaman aşımı (saniye) |
| `HTTP_MAX_RETRIES` | `3` | Geçici hatalarda yeniden deneme sayısı |
| `HTTP_BACKOFF_SECONDS` | `1.5` | Üstel geri çekilme başlangıcı |
| `REQUESTS_PER_MINUTE` | `30` | Adaptörler arası paylaşılan hız sınırı |
| `SCHEDULER_ENABLED` | `false` | Otomatik zamanlanmış kontrol (MVP'de kapalı) |
| `DEFAULT_CHECK_INTERVAL_MINUTES` | `60` | Varsayılan kontrol aralığı |
| `OTX_API_KEY` | *(boş)* | AlienVault OTX anahtarı (boşsa kısıtlı topluluk erişimi) |
| `OTX_ENABLED` | `true` | OTX kaynağı etkin mi |
| `THREATFOX_API_KEY` | *(boş)* | abuse.ch Auth-Key (**zorunlu**, yoksa kaynak hata verir) |
| `THREATFOX_ENABLED` | `false` | ThreatFox kaynağı etkin mi |
| `MISP_URL` / `MISP_API_KEY` | *(boş)* | Yalnızca yetkili MISP erişimi |
| `MISP_VERIFY_TLS` | `true` | MISP TLS doğrulaması |
| `MISP_ENABLED` | `false` | MISP kaynağı etkin mi |
| `BREACH_FEED_URL` / `BREACH_FEED_API_KEY` | *(boş)* | İzinli breach intelligence akışı (Bearer) |
| `BREACH_FEED_ENABLED` | `false` | Breach akışı etkin mi |
| `DARKWEB_SOURCE_URL` / `DARKWEB_SOURCE_API_KEY` | *(boş)* | İzinli, yapılandırılmış izleme kaynağı |
| `DARKWEB_SOURCE_ENABLED` | `false` | İzleme kaynağı etkin mi (ayrıca izin onayı gerekir) |

> **Not:** Dark Web izleme kaynağı, kullanım koşulları onaylanmadan (`confirmed_authorized` /
> `terms_reviewed`) çalıştırılmaz ve varsayılan olarak kapalıdır.

---

## 4. Çalıştırma (yerel)

```bash
streamlit run app.py
```

Arayüz varsayılan olarak <http://localhost:8501> adresinde açılır. İlk açılışta veritabanı şeması
otomatik oluşturulur ve varsayılan kaynak yapılandırmaları senkronize edilir.

### Demo verisi ve örnek kullanım senaryosu

`data/opentip.db` içinde **sentetik** bir demo veri seti hazır gelir; gerçek müşteri verisi veya
sızdırılmış veri içermez:

| Kayıt | İçerik |
| --- | --- |
| Kurum | `DEMO Kurum` + 4 doğrulanmış varlık (`demo-kurum.example`, `mail.demo-kurum.example`, e-posta alan adı, marka adı) |
| Bulgular | `F-DEMO-001` corroborated/critical · `F-DEMO-002` unverified_claim/high · `F-DEMO-003` confirmed/critical · `F-DEMO-004` false_positive/low |
| Alarmlar | 2 açık alarm (yeni kritik bulgu, durum değişikliği) |
| Kaynaklar | `otx` ve `threatfox` etkin (`.env` içinde anahtar gerekir); diğerleri yapılandırma bekliyor |

Senaryo:

1. **Dashboard** — açık alarm sayısı, bulgu ve IOC sayaçları ile kaynak sağlığı özetini görün.
2. **IOC Analysis** — `example.com` sorgulayın. OTX ve ThreatFox etkin olduğu için kaynak
   tablosunda `ok` durumu görünür; kaynaklardan biri anahtarsız/hatalıysa `error` olarak **ayrı**
   raporlanır ve gösterge "temiz" sayılmaz.
   > Demo varlıklarında kullanılan `demo-kurum.example`, ayrılmış (reserved) `.example` TLD'sinde
   > olduğu için OTX bu alan adını reddeder (HTTP 400). Demo verisinin kendisi yereldir; canlı
   > sorgu için OTX/ThreatFox'un tanıdığı bir alan adı (ör. `example.com`) kullanın.
3. **Breach Intelligence → Sızıntı iddiaları** — `F-DEMO-002`'nin `unverified_claim` (doğrulanmamış
   iddia) olmasına karşın `high` risk taşıdığını doğrulayın. Bu iki alan kasıtlı olarak ayrıdır.
4. **Doğrulama geçişi** — `F-DEMO-002` detayında sıradaki duruma (`in_review` → `confirmed` /
   `false_positive`) ilerletin; geçersiz atlamalar engellenir, her adım denetim kaydına yazılır.
5. **Findings & Reports** — JSON ve HTML raporunu dışa aktarın; çıktı `reports_output/` dizinine
   yazılır ve raporlarda API anahtarı bulunmaz.
6. **Dark Web Monitoring** — kaynakların etkinlik durumunu, son çalışma ve ardışık hata sayısını
   görün; manuel kontrolü tetikleyin.

Demo veriyi sıfırlamak için `data/opentip.db` dosyasını silin; uygulama bir sonraki açılışta boş
şemayı yeniden oluşturur.

---

## 5. Docker

### docker-compose (önerilen)

```bash
copy .env.example .env      # ve gerekli değerleri doldurun
docker compose up -d --build
```

Arayüz: <http://localhost:8501>

```bash
docker compose logs -f opentip     # günlükler
docker compose exec opentip python -m pytest   # konteyner içinde testler
docker compose down                # durdur
```

`docker-compose.yml` iki kalıcı dizini host'a bağlar, böylece konteyner yeniden oluşturulsa da veri korunur:

- `./data` → `/app/data` (SQLite veritabanı)
- `./reports_output` → `/app/reports_output` (JSON/HTML raporları)

`.env` dosyası `env_file` ile çalışma zamanında verilir; imaja gömülmez (`.dockerignore`). İmaj root
olmayan `opentip` kullanıcısıyla çalışır ve `_stcore/health` uç noktasını kontrol eden bir
`HEALTHCHECK` içerir.

### Yalnızca Docker

```bash
docker build -t opentip:latest .
docker run --rm -p 8501:8501 --env-file .env \
  -v "%cd%/data:/app/data" \
  -v "%cd%/reports_output:/app/reports_output" \
  opentip:latest
```

Linux/macOS'ta `-v "$(pwd)/data:/app/data"` biçimini kullanın.

---

## 6. Testler

Testler gerçek ağ erişimi gerektirmez; sahte HTTP oturumu (`FakeSession`) ve sahte adaptörler
kullanılır, her test kendi geçici SQLite veritabanıyla çalışır.

```bash
# Yerel
.venv\Scripts\python -m pytest          # Windows
# .venv/bin/python -m pytest            # Linux / macOS

# Docker
docker compose exec opentip python -m pytest
```

Tek dosya veya tek test:

```bash
.venv\Scripts\python -m pytest tests/test_risk_engine.py -v
.venv\Scripts\python -m pytest tests/test_adapters.py::test_validate_url_blocks_private_and_invalid_targets -v
```

Kapsam (PRD §17 ile eşleşir):

| Test dosyası | Kapsam |
| --- | --- |
| `tests/test_ioc_validator.py` | IOC ayrıştırma, tür tespiti, defang/refang, doğrulama |
| `tests/test_normalizer.py` | Ortak veri modeline dönüştürme, tekilleştirme, parmak izi |
| `tests/test_risk_engine.py` | Risk puanlama, doğrulama durumu geçişleri |
| `tests/test_change_detector.py` | Yeni/değişen/kaybolan kayıt sınıflandırması |
| `tests/test_scheduler.py` | Zamanlanmış görev planlama, tekrar eden kayıt, hata durumu |
| `tests/test_adapters.py` | Adaptör eşleme, hız sınırı/yeniden deneme, SSRF koruması |
| `tests/test_analyzer.py` | Analiz akışı, kaynak hatası izolasyonu, tekilleştirme, bulgu kalıcılığı |
| `tests/test_reports.py` | JSON/HTML rapor üretimi, anahtar temizliği, denetim kaydı |

---

## 7. Dizin yapısı

```text
opentip/
├── app.py                  # Streamlit arayüzü (giriş noktası)
├── config.py               # Ortam değişkenlerinden okunan ayarlar
├── requirements.txt
├── .env.example            # Yapılandırma şablonu (gerçek anahtar içermez)
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── models/                 # Ortak veri modeli ve numaralandırmalar
├── core/                   # Doğrulama, normalizasyon, tekilleştirme, risk, bulgu yönetimi
├── adapters/               # Kaynak adaptörleri (OTX, ThreatFox, MISP, breach, dark web)
├── storage/                # SQLite şeması ve repository'ler
├── monitoring/             # Değişiklik tespiti, zamanlayıcı, bildirimler
├── reports/                # JSON ve HTML rapor dışa aktarma + şablonlar
└── tests/                  # pytest testleri
```

---

## 8. Yeni kaynak ekleme

1. `adapters/` altında `BaseAdapter`'ı uygulayan yeni bir sınıf yazın.
2. `adapters/__init__.py` içindeki `ADAPTER_REGISTRY` sözlüğüne kaydedin.
3. Aynı dosyadaki `default_source_configs()` içinde varsayılan yapılandırmasını tanımlayın.

Analiz motorunun geri kalanının değiştirilmesi gerekmez. Adaptörler `capabilities` kümesiyle
(`CAP_IOC_LOOKUP`, `CAP_FETCH_UPDATES`, `CAP_CONNECTION_CHECK`) yeteneklerini bildirir ve
`BaseAdapter._validate_url()` üzerinden SSRF korumasından geçer.

---

## 9. Sorun giderme

| Belirti | Olası neden / çözüm |
| --- | --- |
| Kaynak "hata" durumunda | API anahtarı eksik ya da geçersiz. `.env` içindeki ilgili değişkeni kontrol edin. |
| ThreatFox doğrulanamıyor | abuse.ch Auth-Key zorunludur; `THREATFOX_API_KEY` girilmeli. |
| Veriler kayboldu (Docker) | `./data` volume'ünün bağlı olduğundan emin olun. |
| Port 8501 kullanımda | `docker compose` portunu değiştirin (`"8502:8501"`). |
| Zamanlanmış kontrol çalışmadı | `SCHEDULER_ENABLED=true` yapın veya arayüzden manuel tetikleyin. |

---

## 10. Lisans ve sorumluluk

Bu platform yalnızca **yetkili** güvenlik araştırmalarında, sahip olunan veya izin verilen varlıklar
üzerinde kullanılmak üzere geliştirilmiştir. Kullanıcı, entegre ettiği her kaynağın kullanım
koşullarına ve yürürlükteki mevzuata uymakla yükümlüdür.
