# Panduan Implementasi IAM Authenc untuk Instansi Pemerintah

Dokumen ini menjelaskan bagaimana menggunakan Authenc untuk mengakomodir struktur organisasi instansi pemerintah yang hierarkis (Pusat, Wilayah, Satuan Kerja) dan manajemen akses berbasis peran (RBAC).

## 1. Konsep Dasar

Authenc memiliki fitur yang dapat dipetakan langsung ke kebutuhan instansi:

| Konsep Instansi | Fitur Authenc | Keterangan |
|-----------------|---------------|------------|
| **Instansi / Kementerian** | **Realm** | Satu "Realm" digunakan untuk satu instansi penuh untuk menjamin Single Sign-On (SSO) di seluruh aplikasi instansi. |
| **Unit Kerja (Pusat/Wilayah/Satker)** | **Groups (Hierarchical)** | Struktur organisasi dipetakan menggunakan Nested Groups. |
| **Jabatan Fungsional (Operator, Validator)** | **Roles** | Peran yang menentukan apa yang *bisa dilakukan* pengguna. |
| **Atribut Pegawai (NIP, Jabatan)** | **User Attributes** | Metadata tambahan yang disimpan dalam profil pengguna. |

## 2. Struktur Hierarki

Authenc mendukung grup bertingkat (Nested Groups). Setiap grup memiliki `path` unik (misal: `/Pusat/Kanwil_Jabar/Kanim_Bandung`).

### Contoh Struktur:
```text
/ (Root)
├── Pusat (Group)
│   ├── Sekretariat Jenderal
│   └── Direktorat Teknis
├── Kanwil Jawa Barat (Group)
│   ├── Kanim Bandung (Group)
│   │   ├── Seksi Lantaskim (Subgroup)
│   │   └── Seksi Inteldakim (Subgroup)
│   └── Kanim Cirebon (Group)
└── Kanwil Jawa Tengah (Group)
    └── ...
```

### Cara Implementasi
1.  Buat Group induk (Pusat).
2.  Buat Group anak (Kanwil) dengan `parent_id` mengarah ke Group Pusat.
3.  Buat Group cucu (Satker) dengan `parent_id` mengarah ke Group Kanwil.

Secara teknis, `path` akan otomatis digenerate oleh sistem: `/Pusat/Kanwil_Jabar/Kanim_Bandung`. Aplikasi klien dapat membaca `path` ini untuk menentukan lingkup data pengguna.

## 3. Manajemen Peran (Roles)

Peran dibagi berdasarkan fungsi, bukan jabatan struktural (kecuali jabatan tersebut memiliki hak akses spesifik di aplikasi).

### Contoh Role:
*   `operator`: Bisa input data.
*   `validator`: Bisa memverifikasi input.
*   `approver`: Bisa menyetujui permohonan (misal: Kepala Kantor).
*   `admin_satker`: Bisa mengelola user di satkernya.
*   `admin_wilayah`: Bisa mengelola user di wilayahnya.
*   `super_admin`: Admin pusat.

### Penugasan (Assignment):
*   **User Budi (Operator di Kanim Bandung):**
    *   Member of Group: `/Kanwil_Jabar/Kanim_Bandung`
    *   Assigned Role: `operator`
*   **User Ani (Kepala Kantor Kanim Bandung):**
    *   Member of Group: `/Kanwil_Jabar/Kanim_Bandung`
    *   Assigned Role: `approver` (atau `kepala_kantor`)

## 4. Administrasi Terdelegasi (Delegated Admin)

Untuk kebutuhan "Admin Wilayah mengelola Satker di bawahnya", ada dua pendekatan:

### Pendekatan A: Logika Aplikasi (Disarankan)
Aplikasi manajemen user (Dashboard Admin) membaca token pengguna.
*   Jika User X punya role `admin_wilayah` dan grup `/Kanwil_Jabar`:
*   Aplikasi menampilkan data user/satker yang grup `path`-nya diawali `/Kanwil_Jabar`.
*   Authenc menyediakan API untuk *query users by group path*.

### Pendekatan B: Atribut Tambahan
Tambahkan atribut kustom pada user admin:
```json
{
  "admin_scope": "/Kanwil_Jabar",
  "jabatan": "Kepala Divisi Administrasi"
}
```

## 5. Kesimpulan

**Apakah bisa?** Ya, sangat bisa.
Authenc sudah memiliki fitur native untuk:
1.  **Multi-tenancy (Realm)** untuk isolasi instansi.
2.  **Hierarchical Groups** untuk struktur Pusat -> Daerah.
3.  **RBAC** untuk pembagian tugas (Operator s/d Kepala Kantor).

Tidak perlu kustomisasi kode inti (core code modification), cukup konfigurasi data (Data Seeding) melalui API atau Database Operation.
