# -----------------------------------------------------------------------------
# GitHub Actions OIDC — federated identity for CI/CD (no long-lived AWS keys)
# -----------------------------------------------------------------------------

# Fetches GitHub Actions' OIDC issuer TLS certificate so AWS can trust that identity provider.
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}


# output "github_live_thumbprint" {
#   value       = data.tls_certificate.github.certificates[0].sha1_fingerprint
#   description = "This is the cryptographic SSL certificate footprint fetched live from GitHub's authorization servers."
# }


# Registers GitHub as an IAM OIDC identity provider so workflows can assume AWS roles via web identity.
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}


# Trust policy: only GitHub Actions from the specified repo/branch may assume the deploy role.
data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:GreatOne33/cloudpipe-deploy:ref:refs/heads/main"]
    }
  }

}


# IAM role that GitHub Actions assumes at deploy time (OIDC → STS → temporary credentials).
resource "aws_iam_role" "github_actions" {
  name               = "github-actions-deployer-${random_string.suffix.result}"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json
}

# Permissions granted to the deploy role: sync site files to S3, invalidate CloudFront, read deploy config from SSM.
data "aws_iam_policy_document" "cicd_execution_permissions" {
  statement {
    sid       = "ListBucketForSync"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.cicd_website_bucket.arn]
  }

  statement {
    sid       = "ManageBucketObjects"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.cicd_website_bucket.arn}/*"]
  }

  statement {
    sid       = "CloudFrontCacheInvalidation"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.cicd_website_distribution.arn]
  }

  statement {
    sid       = "ReadSSMParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:us-east-1:${data.aws_caller_identity.current.account_id}:parameter/config/production/cloudpipe/*"] 
  }
}

# IAM policy document attached to the GitHub Actions deploy role.
resource "aws_iam_policy" "cicd_policy" {
  name        = "github-actions-cicd-policy"
  description = "Tightly scoped data sync, SSM read, and cache invalidation permissions"
  policy      = data.aws_iam_policy_document.cicd_execution_permissions.json
}

# Binds the CI/CD permissions policy to the GitHub Actions IAM role.
resource "aws_iam_role_policy_attachment" "cicd_policy_attach" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.cicd_policy.arn
}


# -----------------------------------------------------------------------------
# S3 — private origin bucket for static website assets (deployed by GitHub Actions)
# -----------------------------------------------------------------------------

# Stores built website files; not served directly to the public (access is via CloudFront only).
resource "aws_s3_bucket" "cicd_website_bucket" {
  bucket = "cloudpipe-vault-${random_string.suffix.result}"
}

# Blocks all public ACLs and bucket policies so objects cannot be exposed on the open internet.
resource "aws_s3_bucket_public_access_block" "cicd_website_bucket_policy" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

# Keeps object history so rollbacks and accidental overwrites are recoverable.
resource "aws_s3_bucket_versioning" "cicd_website_bucket_versioning" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  versioning_configuration {
    status = "Enabled"
  }

}

# Encrypts all objects at rest with SSE-S3 (AES-256).
resource "aws_s3_bucket_server_side_encryption_configuration" "cicd_website_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_wafv2_web_acl" "cloudpipe_waf" {
  name = "cloudpipe-cdn-waf-${random_string.suffix.result}"
  description = "Provides rate limiting and known bad input protections against exploits and billing spikes"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name = "AWS-AWSManagedRulesKnownBadInputsRuleSet" 
    priority = 1

    statement {
      managed_rule_group_statement {
        name = "AWSManagedRulesKnownBadInputsRuleSet" 
        vendor_name = "AWS"
      }
    }
  
    override_action {
      none {}
  }

    visibility_config {
      cloudwatch_metrics_enabled = true 
      metric_name = "WAFKnownBadInputsMetric" 
      sampled_requests_enabled = true
    }
  }

  rule {
    
    name = "IPRateLimit"
    priority = 2
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit = 300
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true 
      metric_name = "IPRateLimitMetric"
      sampled_requests_enabled = true 
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true 
    metric_name = "CloudFrontWAFMetric" 
    sampled_requests_enabled = true 
  }
}

# -----------------------------------------------------------------------------
# CloudFront — CDN in front of S3 (HTTPS, caching, private origin access)
# -----------------------------------------------------------------------------

# Origin Access Control: CloudFront signs requests to S3; bucket stays private without public URLs.
resource "aws_cloudfront_origin_access_control" "cicd_website_oac" {
  name                              = "cloudpipe-oac-${random_string.suffix.result}"
  description                       = "Secures S3 backend so data is readable only via Cloudfront authentication"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"

}

# Global distribution that serves the site from edge locations and pulls content from the S3 bucket.

data "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "Managed-SecurityHeadersPolicy"
}
resource "aws_cloudfront_distribution" "cicd_website_distribution" {
  origin {
    domain_name              = aws_s3_bucket.cicd_website_bucket.bucket_regional_domain_name
    origin_id                = "S3-Website-Origin-Primary"
    origin_access_control_id = aws_cloudfront_origin_access_control.cicd_website_oac.id
  }

  origin {
    domain_name = aws_s3_bucket.cicd_website_backup.bucket_regional_domain_name 
    origin_id = "S3-Website_Origin-Backup" 
    origin_access_control_id = aws_cloudfront_origin_access_control.cicd_website_oac.id 
  }

  origin_group {
    origin_id = "S3-Website-Origin-Group"

    failover_criteria {
      status_codes = [500, 502, 503, 504] 
    }

    member {
      origin_id = "S3-Website-Origin-Primary"
    }

    member {
      origin_id = "S3-Website-Origin-Backup"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  web_acl_id = aws_wafv2_web_acl.cloudpipe_waf.arn
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    target_origin_id       = "S3-Website-Origin-Group"
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6"

    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security_headers.id
  }

  custom_error_response {
    error_code = 403 
    response_code = 200
    response_page_path = "/index.html"
    error_caching_min_ttl = 10
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}


# Bucket policy: allows only this CloudFront distribution to read objects (enforces OAC, not public S3).
data "aws_iam_policy_document" "allow_cloudfront_oac_read" {
  statement {
    sid       = "AllowCloudFrontOACRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.cicd_website_bucket.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["${aws_cloudfront_distribution.cicd_website_distribution.arn}"]
    }
  }
}

# Applies the CloudFront-only read policy to the website bucket.
resource "aws_s3_bucket_policy" "cicd_website_auth" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  policy = data.aws_iam_policy_document.allow_cloudfront_oac_read.json
}


# -----------------------------------------------------------------------------
# SSM Parameter Store — values GitHub Actions reads at deploy time (no secrets in repo)
# -----------------------------------------------------------------------------

# IAM role ARN for the workflow's `aws-actions/configure-aws-credentials` OIDC step.
resource "aws_ssm_parameter" "cicd_role_arn" {
  name        = "/config/production/cloudpipe/cicd_role_arn"
  type        = "String"
  value       = aws_iam_role.github_actions.arn
  description = "The exact execution IAM Role ARN needed for the GitHub OIDC Handshake"
}

# Target S3 bucket name for `aws s3 sync` (or equivalent) in the deploy job.
resource "aws_ssm_parameter" "cicd_website_bucket" {
  name        = "/config/production/cloudpipe/cicd_website_bucket"
  type        = "String"
  value       = aws_s3_bucket.cicd_website_bucket.id
  description = "The S3 bucket name for the CICD website"
}

# CloudFront distribution ID so the pipeline can create cache invalidations after upload.
resource "aws_ssm_parameter" "cloudfront_distibution_id" {
  name        = "/config/production/cloudpipe/cloudfront_distribution_id"
  type        = "String"
  value       = aws_cloudfront_distribution.cicd_website_distribution.id
  description = "The Edge cache network distribution ID used to trigger global file flushes"
}

resource "github_actions_variable" "oidc_role_var" {
  repository = "cloudpipe-deploy"
  variable_name = "AWS_ROLE_ARN"
  value = aws_iam_role.github_actions.arn
}

resource "aws_s3_bucket" "cicd_website_backup" {
  bucket = "cloudpipe-backup-${random_string.suffix.result}"
}

resource "aws_s3_bucket_public_access_block" "cicd_website_backup_policy" {
  bucket = aws_s3_bucket.cicd_website_backup.id 

  block_public_acls = true 
  block_public_policy = true 
  ignore_public_acls = true 
  restrict_public_buckets = true 
}

resource "aws_s3_bucket_versioning" "cicd_website_backup_bucket_versioning" {
  bucket = aws_s3_bucket.cicd_website_backup.id 

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cicd_website_backup_bucket_encrypt" {
  bucket = aws_s3_bucket.cicd_website_backup.id 

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

