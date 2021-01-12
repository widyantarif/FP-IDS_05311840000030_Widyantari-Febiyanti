# FP-IDS_05311840000030_Widyantari-Febiyanti

## Judul 
Intruder Notification Using Whatsapp Notification

## Penjelasan singkat
Membuat program yang mampu mendeteksi adanya intruder saat mengakses suatu server. Disini dibuat website sederhana dan membuat IDS didalamnya. Akan mendeteksi setiap adanya IP yang mengakses menuju target. 

## Cara Kerja 
1. Membeli server dan menginstallkan website sederhana didalamnya (disini menggunakan nginx) 
2. Mencari referensi program yang ada (disini menggunakan Packet-Sniffer: https://github.com/EONRaider/Packet-Sniffer)
3. Untuk notifikasi ke aplikasi Whatsapp digunakan twilio (https://twilio.com/)
4. Mencari referensi program mpenghubung antara IDS dengan notifikasi Whatsapp 
(disini menggunakan bahasa python dan ada github tentang penghubungnya: https://github.com/twilio/twilio-python)

## Keterangan 
- Nantinya program akan menangkap semua IP yang menuju atau mengakses kedalam website. 
- Selanjutnya akan mengirimkan notifikasi melalui Whatsapp secara otomatis. 
- Program mampu dijalankan dengan Python 3.x

## Keterangan Program 
(sumber: https://github.com/EONRaider/Packet-Sniffer) 

Asumsi intrusi adalah semua paket yang bukan berasal dari IP server itu sendiri.Kemudian IP yang sudah tercatat sebagai intruder, tidak perlu diprint / kirim notifikasi lagi. Yang perlu dilakukan adalah sebagai berikut: 

1. Menambahkan variabel global untuk menyimpan IP intruder:

![1](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture1.png)

2. Menambahkan logika pada fungsi ```_display_packet_info``` serta membuat pengecualian IP yang akan terdeteksi. Pada coding 
```
if self.p.ipv4.source != "103.41.206.73"
```

memiliki arti yaitu melakukan penangkapan kecuali IP ```103.41.206.73``` yang merupakan IP dari server. 

![2](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture2.png)

3. Ketika berhenti, menampilkan list IP yang dianggap intruder:

![3](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture6.png)

4. Install library twilio kedalam server dengan perintah
```pip install twilio```

![4](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture9.png)

(sumber twilio python: https://github.com/twilio/twilio-python)

5. Tambahkan header import sesuai pada petunjuk https://github.com/twilio/twilio-python

![5](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture10.png)

6. Modifikasi ```_display_packet_info``` sesuai dengan petunjuk 

![6](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture11.png) 

```
account_sid = 'zzzzzzzzzzzzzzzzzzzzzzz' ## didapatkan dari login/mendaftar di twilio
auth_token = 'zzzzzzzzzzzzzzzzzzzzzzzz' ## didapatkan dari login/mendaftar di twilio
client = Client(account_sid, auth_token)
message = client.messages.create(
                              from_='whatsapp:+14155238886', ## nomor dari twilio yang harus disave
                              body='Ada intruder dengan IP : ' + lastIP, ## berisikan tulisan/pesan yang akan terkirim
                              to='whatsapp:+zzzzzzzzz' ## nomer kita
                          )
print(message.sid)
getattr(self, '_display_{}_data'.format(proto.lower()))()
```

7. Jalankan program dengan perintah ```python3 packet_sniffer.py``` dan akan didapatkan hasilnya: 

- untuk notifikasi di Whatsapp

![7](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture12.png)

- untuk notifikasi di server

![8](https://github.com/widyantarif/FP-IDS_05311840000030_Widyantari-Febiyanti/blob/main/Dokumentasi/Picture13.png)
