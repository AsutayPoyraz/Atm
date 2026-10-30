# Atm
ATM 1.0 — Dijital Bankacılık ve ATM Simülasyonu 🏦ATM 1.0, modern web teknolojileri ve FastAPI altyapısı kullanılarak geliştirilmiş, tek dosya halinde çalışan tam kapsamlı bir eğitim amaçlı ATM/dijital bankacılık simülasyonudur. Arka planda güvenli şifreleme mekanizmaları ve veritabanı yönetimi barındırırken, ön planda tek sayfalık (SPA) modern ve şık bir arayüz sunar.
✨ Özellikler
🔐 Güvenli Kimlik Doğrulama: PBKDF2-HMAC-SHA256 tabanlı şifre hashleme ve oturum yönetimi (Session TTL).
💰 Kapsamlı Hesap Yönetimi: Vadesiz ve birikim hesapları arasında bakiye takibi ve aktarımı.
💸 Para Çekme ve Yatırma: ATM banknot simülasyonu (200 TL, 100 TL vb.), günlük çekim/transfer limitleri kontrolü.⇄ Hesaplar Arası Transfer: T.C. Kimlik numarası ile anlık havale simülasyonu.
▦ Fatura Ödeme: Elektrik, su, doğalgaz ve internet faturası ödeme simülasyonu.
▤ İşlem Geçmişi ve Raporlama: Gelişmiş filtreleme, arama, sayfalama ve CSV formatında dışa aktarma (Export) desteği.⚙ Güvenlik Ayarları: PIN değiştirme, başarısız denemelerde hesap bloke koruması.
📱 Modern Arayüz: Responsive (mobil uyumlu), karanlık/açık modern tasarım diline sahip gömülü HTML/CSS/JS arayüzü.
👥 Demo HesaplarUygulamayı ilk çalıştırdığınızda veritabanına otomatik olarak şu test hesapları eklenir:Hesap AdıT.C. Kimlik Numarası (TCKN)PINDemo Kullanıcı111111111111234Ayşe Demir222222222220000
🚀 Kurulum ve ÇalıştırmaProjeyi çalıştırabilmek için bilgisayarınızda Python 3.8+ yüklü olmalıdır.Depoyu klonlayın veya Atm 1.0.py dosyasını bilgisayarınıza indirin.Gerekli kütüphaneleri yüklemek için terminalde şu komutu çalıştırın:pip install fastapi uvicorn sqlalchemy
Uygulamayı başlatın:python "Atm 1.0.py"
Tarayıcınızı açın ve aşağıdaki adrese gidin:
👉 http://127.0.0.1:8000🛠️ Kullanılan TeknolojilerBackend: Python, FastAPI, Uvicorn, SQLAlchemy, PydanticVeritabanı: SQLite (atm_v2.db)Frontend: HTML5, CSS3 (Modern Flexbox/Grid ve Custom Properties), Vanilla JavaScript (SPA yapısı)Güvenlik: hashlib, hmac, secrets (PBKDF2 hashing)
⚠️ Yasal / Eğitim Amaçlı UyarıBu uygulama yalnızca eğitim, portfolyo ve prototip geliştirme amacıyla tasarlanmıştır. Gerçek bankacılık işlemleriyle hiçbir bağı yoktur ve gerçek finansal veriler veya gerçek TCKN'ler kullanılmamalıdır.
📄 LisansBu proje eğitim amaçlı açık kaynaklı olarak paylaşılmıştır. Dilediğiniz gibi geliştirebilir ve kullanabilirsiniz.
