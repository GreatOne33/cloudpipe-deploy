# -----------------------------------------------------------------------------
# GitHub Actions OIDC — federated identity for CI/CD (no long-lived AWS keys)
#
# Security model: GitHub proves identity via a short-lived OIDC token; AWS STS
# exchanges it for temporary credentials. No access keys are stored in GitHub
# Secrets, so a leaked repo cannot expose permanent AWS credentials.
# -----------------------------------------------------------------------------

# Fetches GitHub Actions' OIDC issuer TLS certificate so AWS can trust that identity provider.
# The thumbprint pins AWS to the real GitHub token endpoint — not an impersonator.
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}


# output "github_live_thumbprint" {
#   value       = data.tls_certificate.github.certificates[0].sha1_fingerprint
#   description = "This is the cryptographic SSL certificate footprint fetched live from GitHub's authorization servers."
# }


# Registers GitHub as an IAM OIDC identity provider so workflows can assume AWS roles via web identity.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"] # Only AWS STS may consume these tokens (prevents token reuse elsewhere).
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}


# Trust policy: defines WHO may assume the deploy role and under WHAT conditions.
# This is the primary blast-radius control for CI/CD — tighter conditions = smaller attack surface.
data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    # Ensures the token was minted for AWS STS, not a random third-party audience.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match on repo + branch — not StringLike with wildcards.
    # Only workflows on main in this repo can deploy; feature branches and forks are excluded.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:GreatOne33/cloudpipe-deploy:ref:refs/heads/main"]
    }
  }

}


# IAM role that GitHub Actions assumes at deploy time (OIDC → STS → temporary credentials).
# Credentials expire automatically; nothing persistent to rotate or leak from the pipeline.
resource "aws_iam_role" "github_actions" {
  name               = "github-actions-deployer-stable"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json
}

# Least-privilege execution policy — each statement covers one deploy task, scoped to named ARNs only.
# No s3:*, no iam:*, no blanket Resource = "*".
data "aws_iam_policy_document" "cicd_execution_permissions" {
  # ListBucket is required for `aws s3 sync` to enumerate objects before upload/delete.
  statement {
    sid       = "ListBucketForSync"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.cicd_website_bucket.arn, aws_s3_bucket.cicd_website_backup.arn]
  }

  # Object-level CRUD on the two site buckets only — not the log bucket (cfl_center).
  statement {
    sid       = "ManageBucketObjects"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.cicd_website_bucket.arn}/*", "${aws_s3_bucket.cicd_website_backup.arn}/*"]
  }

  # Invalidation is scoped to this distribution ARN — cannot purge another CloudFront distro.
  statement {
    sid       = "CloudFrontCacheInvalidation"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.cicd_website_distribution.arn]
  }

  # Read-only SSM under a fixed prefix — pipeline discovers bucket/role IDs without hardcoding in the repo.
  statement {
    sid       = "ReadSSMParameters"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:us-east-1:*:parameter/config/production/cloudpipe/*"]
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
#
# Security model: buckets are never public. All viewer traffic goes through
# CloudFront + WAF. Direct S3 URLs would bypass edge protections and leak origin.
# -----------------------------------------------------------------------------

# Stores built website files; not served directly to the public (access is via CloudFront only).
# Random suffix avoids global bucket-name collisions and makes targeted guessing harder.
resource "aws_s3_bucket" "cicd_website_bucket" {
  bucket = "cloudpipe-vault-${random_string.suffix.result}"
}

# Defense-in-depth: even if someone later attaches a public bucket policy, these four
# flags block public ACLs, ignore legacy public ACLs, and reject public policies at the account level.
resource "aws_s3_bucket_public_access_block" "cicd_website_bucket_policy" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

# Keeps object history so rollbacks and accidental overwrites are recoverable.
# Also supports forensic recovery if a bad deploy or compromised pipeline uploads malicious content.
resource "aws_s3_bucket_versioning" "cicd_website_bucket_versioning" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  versioning_configuration {
    status = "Enabled"
  }

}

# Encrypts all objects at rest with SSE-S3 (AES-256).
# Meets baseline data-at-rest requirements without customer-managed KMS key overhead for static assets.
resource "aws_s3_bucket_server_side_encryption_configuration" "cicd_website_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.cicd_website_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# -----------------------------------------------------------------------------
# WAF — edge request inspection before traffic reaches CloudFront origins
#
# Security model: filter malicious patterns and throttle abusive IPs at the CDN
# edge. Cheaper and faster than letting bad traffic hit S3; limits billing spikes
# from volumetric or scraping attacks.
# -----------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "cloudpipe_waf" {
  name        = "cloudpipe-cdn-waf-${random_string.suffix.result}"
  description = "Provides rate limiting and known bad input protections against exploits and billing spikes"
  scope       = "CLOUDFRONT" # Must be CLOUDFRONT (not REGIONAL) to attach to a distribution.

  # Default allow: legitimate static-site traffic passes; individual rules below block the bad stuff.
  default_action {
    allow {}
  }

  # AWS-managed rule set — blocks common exploit payloads (SQLi patterns, bad bots, etc.)
  # without maintaining custom regex. override_action none = use AWS's block/allow decisions as-is.
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAFKnownBadInputsMetric"
      sampled_requests_enabled   = true # Sampled logs help tune rules without logging every request.
    }
  }

  # Per-IP rate limit: 300 requests / 5 min window. Blocks sustained scraping or accidental loops
  # that could inflate CloudFront/S3 costs. Legitimate users rarely hit this on a static site.
  rule {
    name     = "IPRateLimit"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 300
        aggregate_key_type = "IP" # Count per source IP — simple, effective for anonymous traffic.
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IPRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CloudFrontWAFMetric"
    sampled_requests_enabled   = true
  }
}

# -----------------------------------------------------------------------------
# CloudFront — CDN in front of S3 (HTTPS, caching, private origin access)
#
# Security model: CloudFront is the only public entry point. OAC signs origin
# requests so S3 stays private. WAF sits in front. TLS is enforced for viewers.
# -----------------------------------------------------------------------------

# Origin Access Control (OAC): CloudFront signs every S3 request with SigV4.
# Replaces legacy OAI — bucket stays fully private; no anonymous S3 reads possible.
resource "aws_cloudfront_origin_access_control" "cicd_website_oac" {
  name                              = "cloudpipe-oac-${random_string.suffix.result}"
  description                       = "Secures S3 backend so data is readable only via Cloudfront authentication"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always" # Every origin request is signed — no unsigned fallback.
  signing_protocol                  = "sigv4"
}

# Look up AWS managed security headers policy by name instead of hardcoding an ID.
# Hardcoded IDs caused NoSuchResponseHeadersPolicy errors; the data source resolves the live ID.
data "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "Managed-SecurityHeadersPolicy"
}

# Global distribution that serves the site from edge locations and pulls content from the S3 bucket.
resource "aws_cloudfront_distribution" "cicd_website_distribution" {
  # Primary origin — live site content synced by GitHub Actions.
  origin {
    domain_name              = aws_s3_bucket.cicd_website_bucket.bucket_regional_domain_name
    origin_id                = "S3-Website-Origin-Primary"
    origin_access_control_id = aws_cloudfront_origin_access_control.cicd_website_oac.id
  }

  # Secondary origin — failover target if primary returns 5xx (availability, not a security boundary).
  origin {
    domain_name              = aws_s3_bucket.cicd_website_backup.bucket_regional_domain_name
    origin_id                = "S3-Website-Origin-Backup"
    origin_access_control_id = aws_cloudfront_origin_access_control.cicd_website_oac.id
  }

  # Origin group: CloudFront tries primary first, fails over to backup on server errors.
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

  # Access logs land in a dedicated private bucket for audit and incident review.
  logging_config {
    include_cookies = false # Cookies may contain session tokens — omit from logs to reduce PII exposure.
    bucket          = aws_s3_bucket.cfl_center.bucket_regional_domain_name
    prefix          = "cloudfront-logs"
  }

  enabled             = true
  is_ipv6_enabled     = true
  web_acl_id          = aws_wafv2_web_acl.cloudpipe_waf.arn # Attach WAF at the edge — all viewer requests inspected.
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]              # Read-only — no POST/PUT/DELETE at the edge (static site).
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"          # Force TLS; plain HTTP never serves content.
    target_origin_id       = "S3-Website-Origin-Group"
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6" # AWS managed CachingOptimized — safe defaults for static assets.

    # Adds HSTS, X-Content-Type-Options, X-Frame-Options, etc. — browser-level hardening at the CDN.
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.security_headers.id
  }

  # SPA fallback: S3 returns 403 for deep links (no object at /app/route). Rewrite to index.html
  # so client-side routing works. Tradeoff: also masks real 403s — acceptable for a public static SPA.
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10 # Short TTL so a misconfigured path isn't cached as index.html for long.
  }

  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["AQ"] # Antarctica — negligible traffic; demonstrates geo filtering capability.
    }
  }

  # checkov:skip=CKV_AWS_174: Using default CloudFront cert for lab training; ACM/Custom domain not attached yet.
  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021" # Drop TLS 1.0/1.1 — only modern cipher suites.
  }
}


# Bucket policy: allows only this CloudFront distribution to read objects (enforces OAC, not public S3).
# The AWS:SourceArn condition is critical — without it, any CloudFront distro could read the bucket.
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
#
# Security model: deploy targets live in AWS, not in GitHub env vars or workflow
# files. The pipeline reads them at runtime with its already-scoped IAM role.
# -----------------------------------------------------------------------------

# IAM role ARN for the workflow's `aws-actions/configure-aws-credentials` OIDC step.
# Hardcoded role name (not Terraform resource ref) keeps the SSM value stable across state changes.
resource "aws_ssm_parameter" "cicd_role_arn" {
  name        = "/config/production/cloudpipe/cicd_role_arn"
  type        = "String"
  value       = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/github-actions-deployer-stable"
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

# Public CloudFront hostname — used by external scanners (e.g. Nuclei); not a secret, safe as String.
resource "aws_ssm_parameter" "cloudfront_domain" {
  name        = "/config/production/cloudpipe/cloudfront_domain"
  type        = "String"
  value       = aws_cloudfront_distribution.cicd_website_distribution.domain_name
  description = "The dynamic endpoint URL of the CloudFront distribution used by Nuclei"
}


# -----------------------------------------------------------------------------
# S3 — backup origin bucket (CloudFront failover)
#
# Same security baseline as primary: private, versioned, encrypted. Failover
# improves availability; it is not a separate security zone.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "cicd_website_backup" {
  bucket = "cloudpipe-backup-${random_string.suffix.result}"
}

resource "aws_s3_bucket_public_access_block" "cicd_website_backup_policy" {
  bucket = aws_s3_bucket.cicd_website_backup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
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


# -----------------------------------------------------------------------------
# S3 — CloudFront access-log sink
#
# Security model: logs contain IPs, URLs, and user agents — treat as sensitive.
# Bucket is private; only CloudFront (via ACL) and account admins should write/read.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "cfl_center" {
  bucket = "cfl-center-${random_string.suffix.result}"
}

# Blocks all public ACLs and bucket policies so objects cannot be exposed on the open internet.
resource "aws_s3_bucket_public_access_block" "cfl_center_policy" {
  bucket = aws_s3_bucket.cfl_center.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

# Keeps object history so rollbacks and accidental overwrites are recoverable.
resource "aws_s3_bucket_versioning" "cfl_center_bucket_versioning" {
  bucket = aws_s3_bucket.cfl_center.id

  versioning_configuration {
    status = "Enabled"
  }

}

# Encrypts all objects at rest with SSE-S3 (AES-256).
resource "aws_s3_bucket_server_side_encryption_configuration" "cfl_center_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.cfl_center.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# BucketOwnerPreferred lets the account owner enforce ACLs — required before setting a private ACL.
resource "aws_s3_bucket_ownership_controls" "cfl_center_ownership" {
  bucket = aws_s3_bucket.cfl_center.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Explicit private ACL — CloudFront logging requires classic ACL write access; private keeps it off the public internet.
resource "aws_s3_bucket_acl" "cfl_center_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.cfl_center_ownership]
  bucket     = aws_s3_bucket.cfl_center.id
  acl        = "private"
}


output "cloudfront_domain" {
  description = "The dynamic domain name of the live cloudfront Distro"
  value       = aws_cloudfront_distribution.cicd_website_distribution.domain_name
}
