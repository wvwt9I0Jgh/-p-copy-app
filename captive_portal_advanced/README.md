# Captive Portal Lab Demo (Gelişmiş)

Bu proje Flask tabanlı bir **captive portal simülasyonu**dur.
- Kullanıcılar butona basarak rızalarını verirler.
- IP adresi maskelenmiş olarak kaydedilir.
- Admin paneli Basic Auth ile korunur.
- Kayıtlar otomatik olarak `RETENTION_DAYS` sonra silinir.

## Çalıştırma (Docker ile)
```bash
docker-compose up --build
```

Tarayıcıdan: http://localhost:8000

Admin Panel: http://localhost:8000/admin
Varsayılan kullanıcı: admin / changeme

> Not: Gerçek dünyada üçüncü kişilerin trafiğini toplamak hukuken yasaktır.
