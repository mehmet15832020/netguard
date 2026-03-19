# NetGuard

Modüler ağ izleme ve güvenlik monitoring sistemi.

## Mimari
```
netguard/
├── agent/        # İzlenen makinelerde çalışan veri toplayıcı
├── server/       # Merkezi veri işleme ve depolama
├── dashboard/    # Gerçek zamanlı web arayüzü
├── shared/       # Ortak veri modelleri ve protokol
├── docs/         # Mimari kararlar ve tasarım notları
├── scripts/      # Kurulum ve deployment scriptleri
└── tests/        # Test dosyaları
```

## Modüller
- **Modül 1 — System Monitor:** CPU, RAM, disk, process izleme
- **Modül 2 — Network Monitor:** Bant genişliği, bağlantı istatistikleri
- **Modül 3 — Traffic Analyzer:** Paket analizi, protokol dağılımı (NDR)
- **Modül 4 — Alert Engine:** Eşik aşımı, anomali bildirimi

## Kurulum
Bkz: `docs/setup.md`
