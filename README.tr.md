<p align="center"><img src="docs/logo.svg" width="72" height="72" alt=""></p>
<h1 align="center">ScanGrid</h1>

[NetSentinel](https://github.com/gorkemguler/net-sentinel) ile aynı Raspberry
Pi çiftinde çalışması için yazdığım küçük, dağıtık bir zafiyet tarayıcı ve
varlık envanteri. Orchestrator iş kuyruğunu, veritabanını, CVE eşleştirmeyi
ve paneli tutuyor; worker işleri alıp `nmap` çalıştırıyor. Bu iki rolü iki
Pi'ye bölebilir, ikisini de tek kartta çalıştırabilir ya da elindeki eski
donanımı tek bir orchestrator'a worker olarak bağlayabilirsin.

*[English README is here](README.md).*

![ScanGrid panosu](docs/screenshot.png)

Ne yapıyor, kısaca:

- **Envanter tutuyor** - ağında gördüğü her host, açık port ve servis
  versiyonu, ilk/son görülme zaman damgasıyla birlikte.
- **Değişiklikleri fark ediyor** - taramalar arasında yeni bir host, yeni
  açılan bir port, versiyonu değişen bir servis, ya da kaybolan bir host.
  Hassas portlar (SSH, RDP, SMB, veritabanları) daha yüksek önemle işaretlenir.
- **CVE eşleştiriyor** - servis banner'larından, NVD API üzerinden ya da
  internete çıkmak istemiyorsan offline bir feed'le. Bu bir triyaj yardımcısı,
  kesin hüküm değil - bir bulguyu doğrulamadan aksiyon alma.
- **Haber veriyor** - ntfy, Telegram ya da webhook, hangisini kurarsan.

Baştan söylemekte fayda var: bu sadece izin verdiğin şeyi tarar. Her hedef
`SCANGRID_ALLOWLIST` içinde çözülmek zorunda - bu kontrol hem iş
oluşturulurken hem de worker `nmap`'i çalıştırmadan hemen önce tekrar
yapılıyor. Public IP'ler bilerek izin vermediğin sürece reddediliyor, `nmap`
argümanları da temizleniyor - exploit/brute-force/DoS script kategorileri
komuta ulaşmadan çıkarılıyor. Buna bir şey yöneltmeden önce
[`docs/SAFETY.md`](docs/SAFETY.md) dosyasını oku.

---

## Mimari

```
   ┌──────────────────────────────┐          ┌───────────────────────────┐
   │ Pi #2 - orchestrator         │  Bearer  │ Pi #1 - worker            │
   │                              │  HTTP    │                           │
   │  FastAPI  /api/*             │◄─────────│  poll /api/worker/claim   │
   │  iş kuyruğu (SQLite/WAL)     │  claim   │  allowlist yeniden kontrol│
   │  ingest → envanter + diff    │─────────►│  run: nmap -sV ...        │
   │  CVE zenginleştirme (NVD)    │  result  │  XML parse → sonuç POST   │
   │  panel + bildirim            │          │  (N worker desteklenir)   │
   │  APScheduler (kuyruk/temizlik)│          │                           │
   └──────────────────────────────┘          └───────────────────────────┘
```

Tek paket, `scangrid`. `SCANGRID_ROLE` ve bir CLI alt komutu hangi yarının
hangi süreç olacağına karar veriyor, her systemd unit'i kendi rolünü
sabitliyor, yani ikisini tek kartta çalıştırmana bir engel yok. Veritabanına
sadece orchestrator dokunuyor. Detay için
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Gerekenler

İki hafif Python servisi. Tek gerçek yük artışı worker'da çalışan `nmap` -
varsayılan argümanlarla o da yumuşak.

### Role göre donanım seçimi

| Kurulum | Asgari | Benim tercihim | Gerçek RAM |
|---|---|---|---|
| sadece orchestrator | Pi 3B, 1 GB | Pi 4B 2 GB | ~110–170 MB |
| sadece worker | Zero 2 W / Pi 3B | Pi 4B 2 GB | ~40–80 MB boşta, nmap sıçratır |
| tek Pi'de ikisi | Pi 3B, 1 GB | Pi 4B 2 GB | ev ağı için yeterli |
| daha fazla worker | 1 orchestrator + istediğin kadar worker | 2 GB'lık bir orchestrator | tek orchestrator, çok worker |

3B'den yukarısı çalışır. Tek istisna `SCANGRID_CVE_PROVIDER=offline` - NVD
feed'lerini indekslemek 300–600 MB RAM istiyor, o yüzden 2 GB'lık bir kartta
`nvd_api` (varsayılan) kullan. Üst tarafta sınır yok; worker ekledikçe paralel
tarama artar (`SCANGRID_WORKER_CONCURRENCY` her birinin ne kadar iş
alacağını belirler).

### SD kart

| | Boyut |
|---|---|
| Asgari (`nvd_api` / `none`) | 8 GB |
| Benim tercihim | 16–32 GB |
| `cve_provider=offline` kullanıyorsan | +10–15 GB feed'ler için |
| 64 GB'lık bir kart | ikisi için de fazlasıyla yeter |

`scan_history_keep` (varsayılan hedef başına 20 tarama) veritabanının sınırsız
büyümesini engelliyor.

### Yazılım

- Raspberry Pi OS Lite 64-bit (Bookworm) ya da Ubuntu Server 24.04, Python 3.11+.
- Kurulum için `git` ve `python3-venv`.
- `nmap` + `libcap2-bin`, sadece worker'da - orchestrator'ın ikisine de
  ihtiyacı yok.
- `-sS` (SYN taraması) worker'da `CAP_NET_RAW` istiyor, systemd unit'i bunu
  veriyor. Yetkilerle uğraşmak istemiyorsan `SCANGRID_DEFAULT_NMAP_ARGS`'ı
  `-sT` (düz connect taraması) kullanacak şekilde ayarla.
- Worker'ın sadece orchestrator'a giden HTTPS'e ihtiyacı var. Orchestrator'ın
  internete ihtiyacı sadece NVD API için - `cve_provider=offline` ya da
  `none` ile bunu da kapatabilirsin.

---

## Çalıştırma seçenekleri

### İki Pi (referans kurulum)

```
 Pi #1  "pi-worker"                     Pi #2  "pi-orchestrator"
 SCANGRID_ROLE=worker  ──claim/result──►  SCANGRID_ROLE=orchestrator
 nmap çalıştırır                        kuyruk + API + panel :8090
```

Laptop'undan:

```bash
git clone https://github.com/gorkemguler/scan-grid.git
cd scan-grid/deploy/ansible
cp inventory.example.ini inventory.ini     # IP'ler, token, ALLOWLIST, orchestrator_url
ansible-playbook -i inventory.ini site.yml
```

Sonra orchestrator üzerinde:

```bash
set -a; . /etc/scangrid/scangrid.env; set +a
/opt/scangrid/venv/bin/scangrid check-allowlist 192.168.1.0/24     # önce dry-run
/opt/scangrid/venv/bin/scangrid add-target home 192.168.1.0/24 --every 1440 --scan-now
```

Panel `http://<orchestrator-pi>:8090/` adresinde. Elle kurmak istersen
[`docs/SETUP.md`](docs/SETUP.md).

### Tek Pi'de iki iş birden

Ev ağı için gayet yeterli. Worker'ın varsayılan `SCANGRID_ORCHESTRATOR_URL`
değeri zaten `http://127.0.0.1:8090`, ekstra bir bağlantı kurman gerekmiyor.

```
 Pi #1  "pi-scangrid"
   ├─ scangrid-orchestrator.service  :8090
   └─ scangrid-worker.service        (→ http://127.0.0.1:8090)
```

İki kurulum script'ini de aynı kutuda çalıştır - `SCANGRID_ALLOWLIST` tek bir
`/etc/scangrid/scangrid.env` dosyasında yaşıyor, iki servis de oradan okuyor:

```bash
sudo NS_ALLOWLIST=192.168.1.0/24 deploy/scripts/install-orchestrator.sh
sudo NS_ALLOWLIST=192.168.1.0/24 deploy/scripts/install-worker.sh
systemctl status scangrid-orchestrator scangrid-worker --no-pager
```

Ansible ile: aynı host'u hem `[orchestrator]` hem `[worker]` altına yaz -
`inventory.example.ini` içinde yorumlu bir örnek var. Ya da `docker compose up
--build`, ardından `docker compose exec orchestrator scangrid add-target self
127.0.0.1 --every 0 --scan-now`. Hızlı denemek için bir terminalde `scangrid
orchestrator &`, diğerinde `SCANGRID_ROLE=worker scangrid worker` de işi görür.

### Tek orchestrator, bir sürü worker

Her worker'ın `SCANGRID_ORCHESTRATOR_URL`'ini orchestrator'a yönlendir, her
birine ayrı bir `SCANGRID_WORKER_ID` ver, aynı token ve allowlist'i paylaştır.
İşler ilk çeken worker'a gider - birden fazla VLAN'ı paralel taramak için
kullanışlı.

---

## Pi olmadan denemek (kendinden başka bir şey taramadan)

```bash
docker compose up --build
# orchestrator http://localhost:8090
# bir worker container'ı 127.0.0.1'i tarar, compose ortamında allowlist'te
```

ya da:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
scangrid gen-token
echo "SCANGRID_ALLOWLIST=127.0.0.1/32" >> .env       # localhost'u tarayabilelim diye
scangrid selftest
scangrid orchestrator       # 1. terminal
SCANGRID_ROLE=worker scangrid worker   # 2. terminal, nmap kurulu olmalı
scangrid add-target local 127.0.0.1 --every 0 --scan-now
```

---

## Yapılandırma

`SCANGRID_` önekli ortam değişkenleri, bir `.env` dosyası otomatik okunuyor.
En çok işine yarayacaklar:

| Değişken | Varsayılan | Not |
|---|---|---|
| `SCANGRID_ROLE` | `orchestrator` | `orchestrator` ya da `worker` |
| `SCANGRID_API_TOKEN` | - | paylaşılan sır; `scangrid gen-token` |
| `SCANGRID_ALLOWLIST` | RFC1918 aralıkları | asıl güvenlik rayı - CIDR, IP ya da `a.b.c.d-e` |
| `SCANGRID_ALLOW_PUBLIC_TARGETS` | `false` | public bir şey taramadan önce `true` olmalı |
| `SCANGRID_ORCHESTRATOR_URL` | `http://127.0.0.1:8090` | worker'ın rapor verdiği yer |
| `SCANGRID_DEFAULT_NMAP_ARGS` | `-sS -sV -T3 --top-ports 1000 -Pn --version-light` | hedef başına ezilebilir |
| `SCANGRID_CVE_PROVIDER` | `nvd_api` | `nvd_api`, `offline` ya da `none` |
| `SCANGRID_NVD_API_KEY` | - | varsa NVD hız limitini yükseltir |
| `SCANGRID_NOTIFY_BACKEND` | `log` | `none` / `log` / `ntfy` / `telegram` / `webhook` |

Geri kalan her şey [`.env.example`](.env.example) içinde.

---

## API

Swagger `/docs` altında, tam referans [`docs/API.md`](docs/API.md) içinde.

| Metod | Yol | Amaç |
|---|---|---|
| `GET`/`POST` | `/api/targets` | hedefleri listele ya da oluştur |
| `PATCH`/`DELETE` | `/api/targets/{id}` | düzenle ya da sil |
| `POST` | `/api/targets/{id}/scan` | hemen bir tarama kuyruğa al |
| `GET` | `/api/targets/{id}/preview` | kapsamda ne var, ne reddedildi |
| `GET` | `/api/hosts`, `/api/hosts/{ip}` | varlık envanteri |
| `GET` | `/api/findings` | CVE eşleşmeleri (`?min_cvss=7&severity=high`) |
| `POST` | `/api/findings/{id}/mute` | yanlış pozitifi sustur |
| `GET` | `/api/changes` | diff kaydı |
| `GET` | `/api/jobs`, `/api/scans`, `/api/stats` | kuyruk ve çalışma geçmişi |
| `POST` | `/api/worker/claim`, `/api/worker/jobs/{id}/result` | worker'ların orchestrator'la konuşma şekli |

---

## CVE verisi üzerine birkaç not

`nvd_api` (varsayılan), her benzersiz ürün/versiyon için `cve_cache_days`
başına (varsayılan bir hafta) en fazla bir kez NVD API'ye gidiyor. API
anahtarın yoksa yaklaşık 6.5 saniyede bir isteğe kısıtlanıyor, yani yoğun bir
ağda ilk zenginleştirme geçişi biraz sürüyor - nvd.nist.gov/developers/request-an-api-key
adresinden ücretsiz bir anahtar alırsan bu ~0.7 saniyeye iniyor.

`offline`, kendi indirdiğin NVD JSON feed'lerine karşı eşleştirme yapıyor
(`deploy/scripts/fetch-nvd-feeds.sh`) - birkaç gigabayt, indekslemesi bir-iki
dakika, o sırada 300–600 MB RAM kullanıyor. Sadece orchestrator'ın hiç
internete çıkmadığı durumlarda mantıklı.

---

## Testleri çalıştırmak

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest
```

## Lisans

MIT - bkz. [`LICENSE`](LICENSE).
