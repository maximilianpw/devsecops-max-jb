SBOM CycloneDX **réelles** générées par Syft 1.55.0 :

```sh
docker pull --platform linux/$ARCH busybox:1.37
docker save --platform linux/$ARCH -o image.tar busybox:1.37
syft scan docker-archive:image.tar -o cyclonedx-json=$ARCH.cdx.json
python3 scripts/ci/image_archive.py describe image.tar > $ARCH.image.json
```

`<arch>.image.json` est la sortie de `image_archive.py describe` (Image ID,
plateforme, DiffIDs). Elles servent à tester `scripts/ci/sbom_identity.py` sur
le format réel de Syft, pas sur un format supposé.
