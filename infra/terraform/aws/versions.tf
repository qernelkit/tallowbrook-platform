terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = { source = "hashicorp/aws", version = "6.68.0" }
    tls = { source = "hashicorp/tls", version = "4.4.1" }
  }

  backend "s3" {
    bucket       = "tb-platform-terraform-state"
    key          = "aws/prod.tfstate"
    region       = "us-east-2"
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Owner       = "platform"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# CloudFront only accepts ACM certificates issued in us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Owner       = "platform"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
