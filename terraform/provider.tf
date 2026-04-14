terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }

  # -----------------------------------------------------------------------
  # BACKEND CONFIGURATION
  # -----------------------------------------------------------------------
  # Uncomment and customize ONE of these backend blocks for your environment.
  # Option A: S3 backend (recommended for shared/team use)
  # backend "s3" {
  #   bucket         = "YOUR-STATE-BUCKET"
  #   key            = "itp-demo/terraform.tfstate"
  #   region         = "us-east-2"
  #   dynamodb_table = "YOUR-LOCK-TABLE"
  #   encrypt        = true
  # }
  #
  # Option B: Local backend (simplest for single-user)
  # (No backend block needed - Terraform uses local by default)
  # -----------------------------------------------------------------------
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "okta-itp-demo"
      ManagedBy = "terraform"
    }
  }
}

# Attacker Lambda runs in a different region to trigger geo-based detection
provider "aws" {
  alias  = "attacker"
  region = var.attacker_region

  default_tags {
    tags = {
      Project   = "okta-itp-demo"
      ManagedBy = "terraform"
    }
  }
}
