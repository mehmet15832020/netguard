# NetGuard — Zeek configuration
# JSON çıktı + rotation kapatma

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 0secs;

# Yüksek hacimli conn loglarını filtrele — sadece anormal bağlantılar
redef Conn::default_logged_state_filters += {
    [Conn::ESTABLISHED] = F,
};
