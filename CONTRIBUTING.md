# Contributing to Authence

Terima kasih telah tertarik berkontribusi pada Authence!

## Cara Kontribusi
1. Fork repository dan buat branch baru dari `main`.
2. Lakukan perubahan (fitur, bugfix, dsb) secara modular.
3. Tambahkan/memperbarui test jika perlu.
4. Pastikan semua test lulus dengan `cargo test` dan kode lolos `cargo clippy`.
5. Buat pull request ke branch `main`.

## Standar Kode
- Ikuti idiom Rust, gunakan clippy/lint.
- Modular, separation of concern, dokumentasi pada fungsi/endpoint baru.
- Fitur keamanan (JWT, session, TOTP, RBAC, audit log) wajib diuji, tidak ada secret ke disk/log.
- Endpoint baru: wajib test, dokumentasi, dan terdaftar di modul API.
- Plugin: API stabil, dokumentasi jelas.

## Commit
- Pesan commit jelas dan deskriptif.
- Satu commit untuk satu perubahan logis.

## Review
- PR direview maintainer, diskusi/revisi sangat dianjurkan.

## Lain-lain
- Lihat `README.md` dan `docs/EXAMPLES.md` untuk referensi API.
- Bug/fitur via Issues.
- Kontribusi keamanan, compliance, modularisasi, plugin, best practice sangat diutamakan.

## Informasi Tambahan
- [CHANGELOG.md](CHANGELOG.md) untuk riwayat perubahan.
- [LICENSE](LICENSE) untuk lisensi proyek.

Terima kasih atas kontribusinya!
Selamat berkontribusi!
- Lihat [LICENSE](LICENSE) untuk lisensi proyek.
