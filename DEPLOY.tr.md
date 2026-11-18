# mini-siem'i bir VPS'e kurmak

🇬🇧 [English](DEPLOY.md)

Bu rehber, nginx üzerinden zaten bir production (canlı) web sitesi sunan bir
Debian/Ubuntu VPS'i varsayar. mini-siem, o makinede **pasif ve salt okunur bir
misafir** olacak şekilde tasarlandı:

| Yaptığı | Yapmadığı |
|---|---|
| `/var/log/auth.log` ve `/var/log/nginx/access.log` dosyalarını okur (ya da journald) | nginx'i, sshd'yi, güvenlik duvarını, fail2ban'ı veya web sitesini değiştirmez |
| Kendi SQLite veritabanını yazar (Docker volume'u veya `/var/lib/mini-siem`) | hiçbir public port açmaz (dashboard `127.0.0.1` adresine bağlanır) |
| `api.telegram.org` adresine giden HTTPS istekleri yapar (yalnızca yapılandırılmışsa) | IP engellemez, aktif bir müdahalede bulunmaz |
| En fazla 0,5 CPU ve yaklaşık 256-300 MB RAM kullanır (zorunlu limitler) | root olarak çalışmaz |

İki kurulum yönteminden **birini** seç: Docker (A) veya systemd (B).

---

## 0. Başlamadan önce

1. Hangi log dosyalarının var olduğunu kontrol et:

   ```bash
   ls -l /var/log/auth.log /var/log/nginx/access.log
   # -rw-r----- 1 syslog   adm ... /var/log/auth.log
   # -rw-r----- 1 www-data adm ... /var/log/nginx/access.log
   ```

   İkisi de `adm` grubu tarafından okunabilir olmalı (Debian/Ubuntu
   varsayılanı budur). Eğer `/var/log/auth.log` **yoksa** (Debian 12 minimal
   ve rsyslog içermeyen diğer sistemlerde böyledir), systemd kurulumu (B) ile
   journald kaynağını kullan; dosyalarla çalışmak istersen `apt install rsyslog`
   komutunu çalıştır.

2. nginx log formatını kontrol et. mini-siem varsayılan `combined` formatını
   bekler. Siten Cloudflare ya da başka bir proxy'nin arkasındaysa nginx'in
   gerçek istemci IP'sini loglamasından emin ol (`set_real_ip_from` +
   `real_ip_header`); aksi halde her istek proxy'den geliyormuş gibi görünür.
   Bu, senin kendi isteğinle yapacağın bir nginx değişikliğidir; mini-siem
   nginx'i asla değiştirmez.

3. Kendi IP adres(ler)ini not al. Böylece bunları `config.yml` içindeki
   `ignore_networks` listesine ekleyip kendin için hiç alarm üretmezsin.

4. (İsteğe bağlı) Bir Telegram botu oluştur: `@BotFather` ile konuş, `/newbot`
   komutunu gönder, token'ı kopyala. Botuna herhangi bir mesaj gönder, sonra
   `https://api.telegram.org/bot<TOKEN>/getUpdates` adresini aç ve `chat.id`
   değerini kopyala.

5. (İsteğe bağlı) GeoIP: README'deki "GeoIP" bölümüne bak. Veritabanı yoksa
   ülkeler "unknown" (bilinmiyor) olarak görünür, geri kalan her şey çalışır.

---

## A. Docker ile kurulum

Compose v2.24 veya daha yeni bir sürümü olan Docker Engine gerekir
(`docker compose version`).

```bash
# 1. Kodu al (normal kullanıcınla)
git clone https://github.com/rosko35/mini-siem.git ~/mini-siem
cd ~/mini-siem

# 2. Gizli bilgiler (secrets)
cp .env.example .env
chmod 600 .env
nano .env            # TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, isteğe bağlı dashboard kimlik doğrulaması

# 3. config.yml dosyasını gözden geçir: ignore_networks, retention_days, log yolları
nano config.yml

# 4. İsteğe bağlı GeoIP veritabanı
cp /path/to/GeoLite2-Country.mmdb geoip/

# 5. Build et ve başlat
docker compose up -d --build
docker compose logs -f          # "monitoring 2 source(s) with 11 rules" satırını ara
```

Compose dosyasının garanti ettikleri (doğrulamak için `docker-compose.yml`
dosyasını oku):

- `/var/log` **salt okunur** (read-only) bağlanır; `/etc/localtime` de salt
  okunur bağlanır, böylece klasik syslog zaman damgaları sunucunun saat
  dilimine göre yorumlanır.
- Container, uid 10001 ile ve ek grup olarak `adm` (gid 4) ile çalışır;
  `cap_drop: ALL`, `no-new-privileges` ve salt okunur bir root dosya sistemi
  kullanılır.
- Yayınlanan tek port `127.0.0.1:8080` adresidir ve internetten erişilemez.
  Docker'ın loopback'e bağlı bir port için kullandığı iptables kuralları
  hiçbir şeyi dışarıya açmaz.
- CPU, bellek, PID ve log boyutu limitleri, uygulamanın web sitesiyle kaynak
  için yarışmasını engeller.

Güncelleme: `git pull && docker compose up -d --build`. Veriler `siem-data`
volume'unda durur ve güncellemelerde silinmez. Her şeyi kaldırmak için:
`docker compose down -v`.

Container'ın logları okuyabildiğini kontrol et:

```bash
docker compose exec siem head -n1 /var/log/auth.log /var/log/nginx/access.log
```

---

## B. systemd ile kurulum (Docker olmadan)

Python 3.11+ gerekir (Debian 12, Ubuntu 24.04). Python 3.10 olan Ubuntu
22.04'te Docker kullan.

```bash
sudo apt install python3-venv            # zaten kurulu değilse
git clone https://github.com/rosko35/mini-siem.git
cd mini-siem
sudo ./deploy/install.sh                 # kurar, henüz başlatmaz
sudo nano /etc/mini-siem/config.yml      # yollar, ignore_networks, retention
sudo nano /etc/mini-siem/env             # Telegram token / chat id, dashboard kimlik doğrulaması
sudo systemctl enable --now mini-siem
journalctl -u mini-siem -f
```

Script şunları yapar: `minisiem` adlı bir sistem kullanıcısı oluşturur
(shell'i ve home dizini yoktur, `adm` grubunun üyesidir); kodu ve bir
virtualenv'i `/opt/mini-siem` altına kurar (sahibi root'tur);
`/etc/mini-siem/config.yml` ve `/etc/mini-siem/env` dosyalarını yalnızca
yoksa oluşturur; `deploy/mini-siem.service` dosyasını kurar. Hiçbir paket
kurmaz ve başka hiçbir servise dokunmaz.

Servis tanımı (unit) ağır biçimde sandbox'lanmıştır (`ProtectSystem=strict`,
`ReadOnlyPaths=/var/log`, hiç capability yok, `MemoryMax=300M`,
`CPUQuota=50%`, `Nice=10`). İncelemek için:
`systemd-analyze security mini-siem`.

**auth.log yerine journald kullanmak için:** `/etc/mini-siem/config.yml`
içinde `auth` dosya kaynağını sil ve şunu etkinleştir:

```yaml
  - type: journald
    identifiers: [sshd, sshd-session]
```

Güncelleme: `git pull && sudo ./deploy/install.sh && sudo systemctl restart mini-siem`
(config, env ve kural dosyaların korunur). Kaldırma:
`sudo ./deploy/install.sh --uninstall` (config'i, veriyi ve kullanıcıyı da
silmek için `--purge` ekle).

---

## Dashboard'a erişmek

Dashboard hiçbir zaman public bir arayüzde dinlemez. Kendi bilgisayarından bir
SSH tüneli kullan:

```bash
ssh -N -L 8080:127.0.0.1:8080 you@your-server
# sonra http://localhost:8080 adresini aç
```

`SIEM_DASHBOARD_USER` / `SIEM_DASHBOARD_PASSWORD` değişkenlerini ayarlamak
ikinci bir katman olarak HTTP basic auth ekler (VPS'te başka kişilerin shell
erişimi varsa işe yarar).

Sonuçlarını tam olarak anlamıyorsan dashboard'a proxy yapan bir nginx
`location` **ekleme**; dashboard internete açık olacak şekilde tasarlanmadı.

---

## Çalıştığını doğrulamak

```bash
# başka bir makineden: uydurma bir kullanıcıyla birkaç başarısız SSH girişi
for i in 1 2 3 4 5 6; do ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no nosuchuser@your-server true; done
```

Birkaç saniye içinde loglarda `ALERT HIGH ssh-bruteforce` satırını görmelisin
(`docker compose logs` / `journalctl -u mini-siem`); `batch_interval` saniye
içinde de bir Telegram mesajı gelmelidir. Kendi IP'n `ignore_networks`
içindeyse hiçbir şey tetiklenmez; bu beklenen davranıştır. fail2ban aktifse
kendini banlayabilirsin, bu yüzden testi tek kullanımlık bir adresten yap.

## İşletim (Operations)

| Görev | Docker | systemd |
|---|---|---|
| Loglar | `docker compose logs -f` | `journalctl -u mini-siem -f` |
| Düzenledikten sonra kuralları doğrulama | `docker compose exec siem siem check-rules` | `sudo -u minisiem SIEM_CONFIG=/etc/mini-siem/config.yml /opt/mini-siem/venv/bin/siem check-rules` |
| Kural değişikliklerini uygulama | `docker compose restart` | `sudo systemctl restart mini-siem` |
| README istatistikleri | `docker compose exec siem siem stats --days 30` | `sudo -u minisiem SIEM_CONFIG=/etc/mini-siem/config.yml /opt/mini-siem/venv/bin/siem stats --days 30` |
| Şimdi temizle (prune) | `docker compose exec siem siem prune` | `... siem prune` |

Saklama süresi (retention) her saat otomatik uygulanır (`retention_days`).

## Sorun giderme

- **Hiç olay yok** - kaynak yollarını ve izinleri kontrol et (adım 0) ve
  `log_timezone` değerinin doğru olduğundan emin ol: yanlış saat dilimi
  tespiti durdurmaz ama zamanların kaymış görünmesine yol açar.
- **"tailing ... from end"** - ilk başlatmada mini-siem her dosyanın sonundan
  başlar (geçmişi doldurmaz). Geçmişi bir kereliğine içe aktarmak için:
  `siem replay --parser auth /var/log/auth.log.1` (alarmları susturmak için
  `-q` ekle).
- **Telegram sessiz** - `TELEGRAM_*` değişkenleri ayarlı mı? `min_severity`
  çok yüksek olabilir mi? Başlangıçta log "Telegram notifications enabled"
  der. HTTP hataları token yazılmadan loglanır.
- **Her şey tek bir IP'den geliyor** - nginx bir proxy'nin arkasında; adım
  0.2'ye bak.
