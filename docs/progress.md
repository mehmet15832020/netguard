914e679 fix(snmp): snmp_collector server modülüne taşındı, import hatası düzeltildi
17eeb2b feat(process-monitor): process izleme ve SNMP collector eklendi
ff12e2c feat(auth): JWT authentication, API key sistemi ve rate limiting eklendi
f2e8c60 feat(notifier): email ve webhook alert bildirimi eklendi
b6d2c98 feat(influxdb): kalıcı time-series veri depolama entegrasyonu tamamlandı
f1a574e feat(scripts): agent deploy scripti eklendi, VM2 traffic collector devre dışı
f75dacc fix(storage): traffic summary önceki snapshot'tan korunuyor
4e43208 feat(dashboard): traffic analyzer paneli eklendi
bc11a8f fix(traffic-analyzer): top_src_ips ve top_dst_ips tuple hatası düzeltildi
956ba95 feat(traffic-analyzer): TShark tabanlı paket analizi ve NDR modülü eklendi
0eeb7d6 chore(deps): pyshark eklendi
8b88418 feat(dashboard): network bant genişliği grafikleri ve bağlantı istatistikleri eklendi
eb967dd feat(network-monitor): bant genişliği ve bağlantı istatistikleri eklendi
009907c feat(scripts): şifresiz SSH deploy scripti tamamlandı
0cc5a55 fix(alert-engine): CPU eşiği 80.0'a geri alındı
86f977e feat(alert-engine): alert storage ve endpoint'ler çalışır hale getirildi
5a47687 feat(alert-engine): kural tabanlı alert sistemi eklendi
1d9665a fix(dashboard): server URL VM1'e güncellendi, çoklu agent görünümü çalışıyor
fee872a feat(scripts): agent otomatik kurulum scripti eklendi
2cf8acb fix(server): CORS middleware eklendi, dashboard bağlantısı düzeltildi fix(shared): timezone import eklendi
13df68e feat(server): FastAPI server, storage katmanı ve endpoint testleri eklendi
6d9513c fix(agent): snap ve sanal dosya sistemleri disk listesinden filtrelendi
e4474e9 feat(agent): collector, sender ve main modülleri eklendi
35471b8 fix(shared): Pydantic V2 deprecated json_encoders kaldırıldı
aa835d7 feat(shared): veri modelleri, protokol sabitleri ve ilk testler eklendi
c683d1b chore(env): Python venv ve VS Code yapılandırması eklendi
3759bb8 chore(repo): proje iskelet yapısı oluşturuldu
9c6cc6a Initial commit
\n\n## Sistem Durumu
- VM1 IP: 192.168.203.134 (NetGuard Server, systemd servisi)
- VM2 IP: 192.168.203.142 (Agent, traffic collector devre dışı)
- Ana makine IP: 192.168.203.1 (Agent + InfluxDB)
- InfluxDB URL: http://localhost:8086, org: netguard, bucket: metrics
