# NetGuard — Zeek konfigürasyonu

# JSON çıktı — tüm loglar makine tarafından okunabilir
redef LogAscii::use_json = T;

# 6 saatlik rotation — collector offset kaydeder, rotation güvenli
redef Log::default_rotation_interval = 6hrs;

# Rotation sonrası eski dosyalar: 7 günden eski olanlar silinebilir
# (Zeek bu değişkeni rotation callback'inde kullanır)
redef Log::default_rotation_postprocessor_cmd = "";
