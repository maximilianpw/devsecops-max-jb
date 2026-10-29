variable "IMAGE" {
  default     = "flask-api"
  description = "Nom de l'image sans tag, éventuellement préfixé par le registre."
  validation {
    condition     = IMAGE != ""
    error_message = "IMAGE ne doit pas être vide."
  }
}

variable "TAG" {
  default     = "local"
  description = "Tag de l'image, sans préfixe v pour les releases."
  validation {
    condition     = TAG != ""
    error_message = "TAG ne doit pas être vide."
  }
}

variable "BUILD_SECRET_FILE" {
  default     = "secrets/build_token"
  description = "Chemin du fichier jeton factice, jamais le contenu du secret."
  validation {
    condition     = BUILD_SECRET_FILE != ""
    error_message = "BUILD_SECRET_FILE doit désigner un fichier non vide."
  }
}

variable "CI_PLATFORM" {
  default     = "linux/amd64"
  description = "Plateforme unique de app-ci ; indépendante de celle de l'hôte."
  validation {
    condition     = contains(["linux/amd64", "linux/arm64"], CI_PLATFORM)
    error_message = "CI_PLATFORM doit être linux/amd64 ou linux/arm64."
  }
}

variable "CACHE_REF" {
  default     = ""
  description = "Cache registre distinct des tags de release ; vide désactive les échanges distants."
  validation {
    condition     = CACHE_REF != "${IMAGE}:${TAG}"
    error_message = "CACHE_REF ne doit pas écraser le tag de l'image."
  }
}

variable "CACHE_EXPORT" {
  default     = false
  description = "Exporte le cache vers CACHE_REF ; la CI ne l'active que sur push de confiance, après audit local."
}

group "default" {
  targets = ["app"]
}

target "app" {
  context    = "."
  dockerfile = "Dockerfile"
  tags       = ["${IMAGE}:${TAG}"]
  platforms  = ["linux/amd64", "linux/arm64"]
  secret     = ["id=package_token,src=${BUILD_SECRET_FILE}"]

  # Les caches de couches ne transportent pas le contenu du montage cache pip.
  cache-from = CACHE_REF != "" ? ["type=registry,ref=${CACHE_REF}"] : []
  # Manifeste d'image (et non index) en gzip : format relu par audit_registry_cache.py.
  cache-to = CACHE_REF != "" && CACHE_EXPORT ? [
    "type=registry,ref=${CACHE_REF},mode=max,image-manifest=true,oci-mediatypes=true,compression=gzip,force-compression=true"
  ] : []

  # Pas de push implicite ; l'archive OCI conserve les deux plateformes.
  output = ["type=oci,dest=dist/app.oci.tar"]
  attest = ["type=provenance,disabled=true", "type=sbom,disabled=true"]
}

target "app-ci" {
  inherits   = ["app"]
  platforms  = [CI_PLATFORM]
  # Chargement local pour Dive, Trivy et Compose, sans reconstruction ultérieure.
  output = ["type=docker"]
}
