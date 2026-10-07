# camera-audit

İzinli laboratuvarlarda ve yönettiğiniz IPv4 ağlarında kamera envanteri ve servis sürümü denetimi yapan komut satırı aracı. Nmap keşfi ve ilk 1000 TCP portu üzerinde hafif sürüm tespiti yapar; tüm canlı cihazları raporlar ve kamera adaylarını kanıtlarıyla gösterir. NVD CPE eşleşmeleri **olası etkilenme** olarak sunulur. Araç sömürü, parola denemesi veya kayıt yapmaz.

## Kurulum

Python 3.11+, Nmap ve ffplay gerekir. macOS'ta `brew install nmap ffmpeg`; Linux'ta dağıtımınızın Nmap ve FFmpeg paketlerini kurun. macOS Keychain veya Linux Secret Service erişimi kamera parolaları için gerekir.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[preview]'
.venv/bin/camera-audit doctor
source .venv/bin/activate
```

Linux'ta masaüstü Secret Service oturumu bulunmuyorsa parola kaydıyla önizleme kullanılamaz; düz metin dosya geri dönüşü yoktur.

## Kullanım

```sh
camera-audit scope add 192.168.1.0/24
camera-audit scope list
camera-audit scan 192.168.1.0/24
camera-audit cameras candidates
camera-audit cameras approve 192.168.1.20 --rtsp-url rtsp://192.168.1.20:554/stream1 --username admin
camera-audit preview 192.168.1.20
camera-audit report
```

`scan` tam CIDR'yi gösterir ve her seferinde onay ister. Özel olmayan izinli bir lab ağı için `scope add CIDR --non-private` kullanın; tarama sırasında CIDR'yi aynen yazarak yeniden onaylayın. Tek kapsam en fazla 4096 IPv4 adresidir. Daha geniş lab ağlarını küçük CIDR'lere ayırın.

ONVIF WS-Discovery bir cihaz adresi bulursa `cameras approve IP` komutu bu adresi kullanabilir. ONVIF adresi yoksa cihazınızın kendi RTSP yolunu `--rtsp-url` ile verin. URL'de kullanıcı adı veya parola kullanmayın; `--username` parolayı gizli istemde alır ve sistem anahtarlığına kaydeder. Sonradan değiştirmek için `camera-audit cameras credentials IP --username NAME` kullanın. `preview` ffplay penceresini açar; Ctrl+C ile kapatılır. Akış bellekte çözümlenip ffplay'e aktarılır; video dosyası oluşturulmaz.

Rapor her taramada terminale yazılır ve uygulama veri dizinindeki `reports/scan-ID.json` dosyasına kaydedilir. `scan --json PATH` veya `report --json PATH` ile başka bir dosya seçebilirsiniz. Veritabanı ve varsayılan rapor dosyaları yalnızca mevcut kullanıcı tarafından okunacak izinlerle oluşturulur. macOS veri dizini `~/Library/Application Support/camera-audit`, Linux veri dizini `${XDG_DATA_HOME:-~/.local/share}/camera-audit` konumudur. Eski alarm uygulamasının dosyaları ve bildirimleri kullanılmaz.

## Bulguların yorumu

NVD sorgusu yalnızca Nmap'in verdiği sürümlü CPE için yapılır. CPE bulunmayan servislerde CVE listesi boş olması güvenli olduğu anlamına gelmez. NVD'ye IP, MAC veya akış bilgisi gönderilmez. Bir CVE çıktığında CPE, port, sürüm, kaynak ve sorgu zamanı rapora eklenir; cihazda zafiyetin gerçekten bulunduğu ayrıca doğrulanmalıdır. Çevrimdışı veya NVD erişilemediğinde önbellek durumu raporlanır.

## Geliştirme

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Testler sahte Nmap XML'i ve mock ağ yanıtları kullanır; gerçek ağ taraması yapmaz.
