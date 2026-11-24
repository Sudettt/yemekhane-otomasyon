import json
import os
import uuid
import bcrypt
from flask import Flask, jsonify, request
import redis

from db import okuma_baglantisi, yazma_baglantisi

app = Flask(__name__)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
OTURUM_SURESI = int(os.getenv("OTURUM_SURESI", "86400"))
MENU_ONBELLEK_SURESI = int(os.getenv("MENU_ONBELLEK_SURESI", "60"))

redis_istemci = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def _kullanici_sozlugu(satir):
    if not satir:
        return None
    kid = satir.get("id") if satir.get("id") is not None else satir.get("kullanici_id")
    sifre_hash = satir.get("sifre_hash") or satir.get("sifre_ozeti") or satir.get("sifre")
    return {
        "id": kid,
        "kullanici_id": kid,
        "ad": satir.get("ad", ""),
        "soyad": satir.get("soyad", ""),
        "eposta": satir.get("eposta", ""),
        "rol": satir.get("rol", "ogrenci"),
        "bakiye": float(satir["bakiye"]) if satir.get("bakiye") is not None else 0.0,
        "ogrenci_no": satir.get("ogrenci_no"),
        "_sifre_hash": sifre_hash,
    }


def _sifre_dogrula(duz_sifre, kayitli):
    if not kayitli:
        return False
    if isinstance(kayitli, bytes):
        kayitli = kayitli.decode("utf-8", errors="ignore")
    kayitli = str(kayitli).strip()
    if kayitli.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(duz_sifre.encode("utf-8"), kayitli.encode("utf-8"))
        except Exception:
            return False
    return duz_sifre == kayitli


def oturum_kullanicisi():
    token = request.headers.get("X-Oturum-Token", "").strip()
    if not token:
        return None
    ham = redis_istemci.get(f"oturum:{token}")
    if not ham:
        return None
    kid = json.loads(ham).get("kullanici_id")
    if not kid:
        return None
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM kullanicilar WHERE id = %s LIMIT 1", (kid,))
            bilgi = _kullanici_sozlugu(cur.fetchone())
        if not bilgi:
            return None
        bilgi.pop("_sifre_hash", None)
        return bilgi
    finally:
        conn.close()


def giris_gerekli():
    k = oturum_kullanicisi()
    if not k:
        return None, (jsonify({"hata": "Giris gerekli."}), 401)
    return k, None


def yonetici_gerekli():
    k, hata = giris_gerekli()
    if hata:
        return None, hata
    if k.get("rol") != "yonetici":
        return None, (jsonify({"hata": "Yonetici yetkisi gerekli."}), 403)
    return k, None


def onbellek_temizle():
    for k in redis_istemci.scan_iter("menuler:*"):
        redis_istemci.delete(k)


@app.get("/api/saglik")
@app.get("/saglik")
def saglik():
    return jsonify({"durum": "tamam"}), 200


@app.post("/api/giris")
def giris():
    g = request.get_json(silent=True) or {}
    eposta = (g.get("eposta") or "").strip().lower()
    sifre = g.get("sifre") or ""
    if not eposta or not sifre:
        return jsonify({"hata": "E-posta ve sifre zorunludur."}), 400
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM kullanicilar WHERE LOWER(eposta) = %s LIMIT 1", (eposta,))
            bilgi = _kullanici_sozlugu(cur.fetchone())
    finally:
        conn.close()
    if not bilgi or not _sifre_dogrula(sifre, bilgi.get("_sifre_hash")):
        return jsonify({"hata": "E-posta veya sifre hatali."}), 401
    bilgi.pop("_sifre_hash", None)
    token = uuid.uuid4().hex
    redis_istemci.setex(f"oturum:{token}", OTURUM_SURESI, json.dumps({"kullanici_id": bilgi["id"]}))
    return jsonify({"token": token, "kullanici": bilgi}), 200


@app.post("/api/kayit")
def kayit():
    g = request.get_json(silent=True) or {}
    ad = (g.get("ad") or "").strip()
    soyad = (g.get("soyad") or "").strip()
    eposta = (g.get("eposta") or "").strip().lower()
    sifre = g.get("sifre") or ""
    rol = (g.get("rol") or "ogrenci").strip().lower()
    ogrenci_no = (g.get("ogrenci_no") or "").strip() or None
    if not ad or not soyad or not eposta or not sifre:
        return jsonify({"hata": "Tum alanlar zorunludur."}), 400
    ozet = bcrypt.hashpw(sifre.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM kullanicilar WHERE LOWER(eposta) = %s LIMIT 1", (eposta,))
            if cur.fetchone():
                return jsonify({"hata": "E-posta zaten kayitli."}), 409
            cur.execute(
                "INSERT INTO kullanicilar (ad, soyad, eposta, sifre_hash, rol, ogrenci_no, bakiye, aktif) VALUES (%s, %s, %s, %s, %s, %s, 0.00, 1)",
                (ad, soyad, eposta, ozet, rol, ogrenci_no),
            )
        conn.commit()
        return jsonify({"mesaj": "Kayit olusturuldu."}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.post("/api/cikis")
def cikis():
    token = request.headers.get("X-Oturum-Token", "").strip()
    if token:
        redis_istemci.delete(f"oturum:{token}")
    return jsonify({"mesaj": "Cikis yapildi."}), 200


@app.get("/api/ben")
def ben():
    k, hata = giris_gerekli()
    if hata:
        return hata
    return jsonify({"kullanici": k}), 200


@app.get("/api/tanimlar")
def tanimlar():
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, ad, konum, kapasite FROM yemekhaneler ORDER BY id")
            yemekhaneler = cur.fetchall()
            cur.execute("SELECT id, ad, sira FROM ogunler ORDER BY sira, id")
            ogunler = cur.fetchall()
            cur.execute("SELECT id, ad FROM alerjenler ORDER BY ad")
            alerjenler = cur.fetchall()
            cur.execute(
                "SELECT y.id, y.ad, y.kalori, y.vejetaryen, k.ad AS kategori FROM yemekler y LEFT JOIN yemek_kategorileri k ON k.id = y.kategori_id ORDER BY y.id"
            )
            yemekler = cur.fetchall()
            for y in yemekler:
                y["vejetaryen"] = bool(y["vejetaryen"])
        return jsonify(
            {
                "yemekhaneler": yemekhaneler,
                "ogunler": ogunler,
                "alerjenler": alerjenler,
                "yemekler": yemekler,
            }
        ), 200
    finally:
        conn.close()


@app.get("/api/menuler")
def menuler():
    tarih = (request.args.get("tarih") or "").strip()
    yemekhane_id = (request.args.get("yemekhane_id") or "").strip()
    ogun_id = (request.args.get("ogun_id") or "").strip()
    haric_alerjen = (request.args.get("haric_alerjen") or "").strip()
    vejetaryen = (request.args.get("vejetaryen") or "").strip() in ("1", "true", "evet")
    key = f"menuler:{tarih}:{yemekhane_id}:{ogun_id}:{haric_alerjen}:{int(vejetaryen)}"
    cached = redis_istemci.get(key)
    if cached:
        return jsonify(json.loads(cached)), 200
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            sql = (
                "SELECT m.id AS menu_id, m.tarih, m.ogrenci_fiyati, m.personel_fiyati, "
                "yh.id AS yemekhane_id, yh.ad AS yemekhane, yh.kapasite, "
                "og.id AS ogun_id, og.ad AS ogun, "
                "COUNT(DISTINCT CASE WHEN r.durum = 'aktif' THEN r.id END) AS aktif_rez, "
                "ROUND(AVG(d.puan), 1) AS ort_puan, COUNT(DISTINCT d.id) AS oy_sayisi "
                "FROM menuler m "
                "JOIN yemekhaneler yh ON yh.id = m.yemekhane_id "
                "JOIN ogunler og ON og.id = m.ogun_id "
                "LEFT JOIN rezervasyonlar r ON r.menu_id = m.id "
                "LEFT JOIN degerlendirmeler d ON d.menu_id = m.id "
                "WHERE 1=1"
            )
            params = []
            if tarih:
                sql += " AND m.tarih = %s"
                params.append(tarih)
            if yemekhane_id:
                sql += " AND m.yemekhane_id = %s"
                params.append(int(yemekhane_id))
            if ogun_id:
                sql += " AND m.ogun_id = %s"
                params.append(int(ogun_id))
            sql += (
                " GROUP BY m.id, m.tarih, m.ogrenci_fiyati, m.personel_fiyati, "
                "yh.id, yh.ad, yh.kapasite, og.id, og.ad, og.sira "
                "ORDER BY m.tarih, og.sira, yh.id"
            )
            cur.execute(sql, params)
            rows = cur.fetchall()
            out = []
            for m in rows:
                cur.execute(
                    "SELECT y.id AS yemek_id, y.ad, y.kalori, y.vejetaryen, "
                    "GROUP_CONCAT(DISTINCT a.ad ORDER BY a.ad SEPARATOR ', ') AS alerjenler, "
                    "GROUP_CONCAT(DISTINCT a.id) AS alerjen_idler "
                    "FROM menu_yemekleri my "
                    "JOIN yemekler y ON y.id = my.yemek_id "
                    "LEFT JOIN yemek_alerjenleri ya ON ya.yemek_id = y.id "
                    "LEFT JOIN alerjenler a ON a.id = ya.alerjen_id "
                    "WHERE my.menu_id = %s "
                    "GROUP BY y.id, y.ad, y.kalori, y.vejetaryen",
                    (m["menu_id"],),
                )
                ym_list = cur.fetchall()
                if vejetaryen and (not ym_list or any(not y["vejetaryen"] for y in ym_list)):
                    continue
                if haric_alerjen:
                    yid = int(haric_alerjen)
                    if any(yid in [int(x) for x in (y["alerjen_idler"] or "").split(",") if x] for y in ym_list):
                        continue
                out.append(
                    {
                        "menu_id": m["menu_id"],
                        "tarih": str(m["tarih"]),
                        "yemekhane_id": m["yemekhane_id"],
                        "yemekhane": m["yemekhane"],
                        "ogun_id": m["ogun_id"],
                        "ogun": m["ogun"],
                        "kapasite": int(m["kapasite"]),
                        "bos_yer": max(0, int(m["kapasite"]) - int(m["aktif_rez"] or 0)),
                        "ogrenci_fiyati": float(m["ogrenci_fiyati"]),
                        "personel_fiyati": float(m["personel_fiyati"]),
                        "toplam_kalori": sum(int(y["kalori"] or 0) for y in ym_list),
                        "ortalama_puan": float(m["ort_puan"]) if m["ort_puan"] is not None else None,
                        "oy_sayisi": int(m["oy_sayisi"] or 0),
                        "yemekler": [
                            {
                                "yemek_id": y["yemek_id"],
                                "ad": y["ad"],
                                "kalori": int(y["kalori"] or 0),
                                "vejetaryen": bool(y["vejetaryen"]),
                                "alerjenler": y["alerjenler"] or "",
                            }
                            for y in ym_list
                        ],
                    }
                )
        payload = {"menuler": out}
        redis_istemci.setex(key, MENU_ONBELLEK_SURESI, json.dumps(payload))
        return jsonify(payload), 200
    finally:
        conn.close()


@app.post("/api/rezervasyonlar")
def rezervasyon_olustur():
    k, hata = giris_gerekli()
    if hata:
        return hata
    menu_id = (request.get_json(silent=True) or {}).get("menu_id")
    if not menu_id:
        return jsonify({"hata": "menu_id zorunludur."}), 400
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.callproc("sp_rezervasyon_yap", [k["id"], int(menu_id)])
            sonuc = cur.fetchone()
            while cur.nextset():
                pass
        conn.commit()
        onbellek_temizle()
        return jsonify({"mesaj": "Rezervasyon olusturuldu.", "sonuc": sonuc or {}}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.get("/api/rezervasyonlarim")
def rezervasyonlarim():
    k, hata = giris_gerekli()
    if hata:
        return hata
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT r.id AS rezervasyon_id, r.menu_id, r.ucret, r.durum, r.olusturma, "
                "m.tarih, yh.ad AS yemekhane, og.ad AS ogun "
                "FROM rezervasyonlar r "
                "JOIN menuler m ON m.id = r.menu_id "
                "JOIN yemekhaneler yh ON yh.id = m.yemekhane_id "
                "JOIN ogunler og ON og.id = m.ogun_id "
                "WHERE r.kullanici_id = %s ORDER BY r.id DESC",
                (k["id"],),
            )
            rows = cur.fetchall()
            for r in rows:
                r["tarih"] = str(r["tarih"])
                r["olusturma"] = str(r["olusturma"])
                r["ucret"] = float(r["ucret"])
        return jsonify({"rezervasyonlar": rows}), 200
    finally:
        conn.close()


@app.post("/api/rezervasyonlar/<int:rez_id>/iptal")
def rezervasyon_iptal(rez_id):
    k, hata = giris_gerekli()
    if hata:
        return hata
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.callproc("sp_rezervasyon_iptal", [k["id"], int(rez_id)])
            sonuc = cur.fetchone()
            while cur.nextset():
                pass
        conn.commit()
        onbellek_temizle()
        return jsonify({"mesaj": "Rezervasyon iptal edildi.", "sonuc": sonuc or {}}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.get("/api/bakiye")
def bakiye_detay():
    k, hata = giris_gerekli()
    if hata:
        return hata
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT bakiye FROM kullanicilar WHERE id = %s LIMIT 1", (k["id"],))
            ks = cur.fetchone()
            cur.execute(
                "SELECT id AS hareket_id, tur, tutar, aciklama, olusturma "
                "FROM bakiye_hareketleri WHERE kullanici_id = %s ORDER BY id DESC LIMIT 50",
                (k["id"],),
            )
            hars = cur.fetchall()
            for h in hars:
                h["tutar"] = float(h["tutar"])
                h["olusturma"] = str(h["olusturma"])
        return jsonify({"bakiye": float(ks["bakiye"]) if ks else 0.0, "hareketler": hars}), 200
    finally:
        conn.close()


@app.post("/api/bakiye/yukle")
def bakiye_yukle():
    k, hata = giris_gerekli()
    if hata:
        return hata
    tutar = (request.get_json(silent=True) or {}).get("tutar")
    if tutar is None:
        return jsonify({"hata": "tutar zorunludur."}), 400
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.callproc("sp_bakiye_yukle", [k["id"], float(tutar)])
            sonuc = cur.fetchone()
            while cur.nextset():
                pass
        conn.commit()
        return jsonify({"mesaj": "Bakiye yuklendi.", "sonuc": sonuc or {}}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.post("/api/turnike/gecis")
def turnike_gecis():
    k, hata = giris_gerekli()
    if hata:
        return hata
    g = request.get_json(silent=True) or {}
    if not g.get("yemekhane_id"):
        return jsonify({"hata": "yemekhane_id zorunludur."}), 400
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.callproc("sp_turnike_gecis", [k["id"], int(g["yemekhane_id"]), (g.get("zaman") or "").strip() or None])
            sonuc = cur.fetchone()
            while cur.nextset():
                pass
        conn.commit()
        onbellek_temizle()
        return jsonify({"mesaj": "Turnike gecisi onaylandi.", "sonuc": sonuc or {}}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.post("/api/degerlendirmeler")
def degerlendirme_kaydet():
    k, hata = giris_gerekli()
    if hata:
        return hata
    g = request.get_json(silent=True) or {}
    if not g.get("menu_id") or g.get("puan") is None:
        return jsonify({"hata": "menu_id ve puan zorunludur."}), 400
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM rezervasyonlar WHERE kullanici_id = %s AND menu_id = %s AND durum = 'kullanildi' LIMIT 1",
                (k["id"], int(g["menu_id"])),
            )
            if not cur.fetchone():
                return jsonify({"hata": "Yalnizca kullandiginiz menuleri degerlendirebilirsiniz."}), 400
            cur.execute(
                "INSERT INTO degerlendirmeler (kullanici_id, menu_id, puan, yorum) VALUES (%s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE puan = VALUES(puan), yorum = VALUES(yorum)",
                (k["id"], int(g["menu_id"]), int(g["puan"]), (g.get("yorum") or "").strip()),
            )
        conn.commit()
        onbellek_temizle()
        return jsonify({"mesaj": "Degerlendirmeniz kaydedildi."}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


@app.get("/api/yonetim/rapor")
def yonetim_rapor():
    _, hata = yonetici_gerekli()
    if hata:
        return hata
    tarih = (request.args.get("tarih") or "").strip()
    conn = okuma_baglantisi()
    try:
        with conn.cursor() as cur:
            sql = (
                "SELECT m.tarih, yh.ad AS yemekhane, og.ad AS ogun, yh.kapasite, "
                "COUNT(DISTINCT CASE WHEN r.durum IN ('aktif', 'kullanildi') THEN r.id END) AS rezerve, "
                "ROUND(AVG(d.puan), 1) AS ortalama_puan, COUNT(DISTINCT d.id) AS oy_sayisi "
                "FROM menuler m "
                "JOIN yemekhaneler yh ON yh.id = m.yemekhane_id "
                "JOIN ogunler og ON og.id = m.ogun_id "
                "LEFT JOIN rezervasyonlar r ON r.menu_id = m.id "
                "LEFT JOIN degerlendirmeler d ON d.menu_id = m.id "
                "WHERE 1=1"
            )
            params = []
            if tarih:
                sql += " AND m.tarih = %s"
                params.append(tarih)
            sql += " GROUP BY m.id, m.tarih, yh.ad, og.ad, yh.kapasite, og.sira ORDER BY m.tarih DESC, og.sira"
            cur.execute(sql, params)
            rows = cur.fetchall()
            for r in rows:
                r["tarih"] = str(r["tarih"])
                kap = int(r["kapasite"] or 0)
                rez = int(r["rezerve"] or 0)
                r["doluluk_yuzde"] = round((rez / kap) * 100, 1) if kap > 0 else 0.0
                r["ortalama_puan"] = float(r["ortalama_puan"]) if r["ortalama_puan"] is not None else None
                r["oy_sayisi"] = int(r["oy_sayisi"] or 0)
        return jsonify({"rapor": rows}), 200
    finally:
        conn.close()


@app.post("/api/yonetim/menuler")
def yonetim_menu_olustur():
    _, hata = yonetici_gerekli()
    if hata:
        return hata
    g = request.get_json(silent=True) or {}
    yemek_idler = g.get("yemek_idler") or []
    if not g.get("tarih") or not g.get("yemekhane_id") or not g.get("ogun_id") or not yemek_idler:
        return jsonify({"hata": "Eksik alan var."}), 400
    conn = yazma_baglantisi()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO menuler (tarih, yemekhane_id, ogun_id, ogrenci_fiyati, personel_fiyati) VALUES (%s, %s, %s, %s, %s)",
                (
                    g["tarih"].strip(),
                    int(g["yemekhane_id"]),
                    int(g["ogun_id"]),
                    float(g["ogrenci_fiyati"]),
                    float(g["personel_fiyati"]),
                ),
            )
            mid = cur.lastrowid
            for yid in yemek_idler:
                cur.execute("INSERT INTO menu_yemekleri (menu_id, yemek_id) VALUES (%s, %s)", (mid, int(yid)))
        conn.commit()
        onbellek_temizle()
        return jsonify({"mesaj": "Yeni menu olusturuldu.", "menu_id": mid}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"hata": str(e)}), 400
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)