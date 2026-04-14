# ==============================================================================
# ITP Demo Videos S3 Bucket
# ==============================================================================
# Dedicated S3 bucket for storing ITP real-mode demo video recordings.
# Videos are uploaded by the trigger_itp_demo.py script (--upload-s3 flag)
# and by GitHub Actions workflows when record_video is enabled.
#
# Features:
#   - 90-day auto-expiration (demo artifacts are disposable)
#   - AES256 server-side encryption
#   - Public access fully blocked
#   - GitHub Actions OIDC role has PutObject/GetObject access
#
# Usage:
#   python3 scripts/trigger_itp_demo.py --mode real \
#     --record-video /tmp/itp-video \
#     --upload-s3 itp-demo-videos-${var.environment} \
#     --aws-profile taskvantage
# ==============================================================================

# --- Look up the GitHub Actions OIDC role ---

data "aws_iam_role" "github_actions" {
  name = "github-taskvantage-joevanhorn"
}

# --- S3 Bucket ---

resource "aws_s3_bucket" "itp_demo_videos" {
  bucket = "itp-demo-videos-${var.environment}"
}

# --- Lifecycle: Auto-expire after 90 days ---

resource "aws_s3_bucket_lifecycle_configuration" "itp_demo_videos" {
  bucket = aws_s3_bucket.itp_demo_videos.id

  rule {
    id     = "expire-after-90-days"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

# --- Encryption: AES256 ---

resource "aws_s3_bucket_server_side_encryption_configuration" "itp_demo_videos" {
  bucket = aws_s3_bucket.itp_demo_videos.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- Block all public access ---

resource "aws_s3_bucket_public_access_block" "itp_demo_videos" {
  bucket = aws_s3_bucket.itp_demo_videos.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- Bucket policy: Allow GitHub Actions role ---

resource "aws_s3_bucket_policy" "itp_demo_videos" {
  bucket = aws_s3_bucket.itp_demo_videos.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubActionsAccess"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_iam_role.github_actions.arn
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject",
        ]
        Resource = "${aws_s3_bucket.itp_demo_videos.arn}/*"
      }
    ]
  })
}

# --- Outputs ---

output "itp_demo_videos_bucket" {
  description = "S3 bucket name for ITP demo video recordings"
  value       = aws_s3_bucket.itp_demo_videos.bucket
}
