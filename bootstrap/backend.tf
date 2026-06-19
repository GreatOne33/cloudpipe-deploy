# backend Tf  
terraform {
  backend "s3" {
    bucket = "aws3-labs-tf-collections"
    key = "projects/cloudpipe-bootstrap/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    use_lockfile = true
  }
}