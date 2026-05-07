import sqlite3

def setup_database():
    # Veritabanı dosyası yoksa oluşturur, varsa bağlanır
    conn = sqlite3.connect('threat_intel.db')
    cursor = conn.cursor()

    # Tehditleri tutacağımız tabloyu oluşturuyoruz
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS known_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT NOT NULL,
        type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        description TEXT
    )
    ''')

    # İçini temizleyelim (scripti birden fazla kez çalıştırırsanız veri kopyalanmasın)
    cursor.execute('DELETE FROM known_threats')

    # Ajanın bulması için örnek siber tehdit verileri
    sample_threats = [
        ('test-phishing.com', 'domain', 'CRITICAL', 'Known credential harvesting domain used in 2025 campaigns.'),
        ('malicious-crypto-site.org', 'domain', 'HIGH', 'Associated with cryptocurrency drainer smart contracts.'),
        ('198.51.100.23', 'ip', 'HIGH', 'Command and Control (C2) server for notorious botnet.'),
        ('suspicious-login-update.net', 'url', 'MEDIUM', 'Newly registered domain mimicking Microsoft login page.')
    ]

    # Verileri tabloya ekleyelim
    cursor.executemany('''
        INSERT INTO known_threats (indicator, type, risk_level, description)
        VALUES (?, ?, ?, ?)
    ''', sample_threats)

    # Değişiklikleri kaydet ve kapat
    conn.commit()
    conn.close()
    
    print(" threat_intel.db başarıyla oluşturuldu ve örnek veriler eklendi!")

if __name__ == '__main__':
    setup_database()