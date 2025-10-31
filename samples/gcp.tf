resource "google_storage_bucket" "public" {
  name          = "my-public-bucket"
  force_destroy = true

  uniform_bucket_level_access = false

  acl = [
    "allUsers:R"
  ]
}

resource "google_compute_firewall" "allow_all" {
  name    = "allow-all"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}
