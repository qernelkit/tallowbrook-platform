# vaultarc

`vaultarc` is the media team's archive tool for CCTV and dash-cam footage held for claims and
investigations. It packs footage into sealed containers, writes drive images for cold storage, signs
manifests, and uploads containers to the archive object store.

## What it does

- Archives are sealed with AES-256/GCM and each manifest carries an RSA-PSS signature.
- Drive images for offline storage use AES-256/XTS.
- A yearly seal over the whole manifest set uses a stateful hash-based signature so it survives the
  survive the review window, which can run to years.
- Passphrase-protected archives come in two formats; `vaultarc restore` reads both.
- Camera ingest (see `src/ingest`) decrypts the camera feed and re-seals it for the archive.

## Usage

```
vaultarc seal   <dir> --out <container>
vaultarc image  <device> --out <image>
vaultarc keygen --out <manifest-key>
vaultarc restore <container> --key <file>
vaultarc upload <container>
```

Run `vaultarc --help` for the full list.
