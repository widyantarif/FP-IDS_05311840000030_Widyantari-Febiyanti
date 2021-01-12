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

5. 
