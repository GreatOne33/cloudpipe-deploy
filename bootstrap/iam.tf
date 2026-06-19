# 1. The Stable OIDC Trust Connection
data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      # Points directly to your app repository
      values   = ["repo:GreatOne33/cloudpipe-deploy:*"]
    }
  }
}

# 2. The Permanent Deployment Role (STABLE NAME)
resource "aws_iam_role" "github_actions" {
  name               = "github-actions-deployer-stable"
  assume_role_policy = data.aws_iam_policy_document.github_actions_trust.json
}

# 3. The State Storage Permission Lock
resource "aws_iam_role_policy" "github_actions_state_policy" {
  name = "CloudPipeTerraformStatePolicy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowTerraformRemoteStateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::aws3-labs-tf-collections",
          "arn:aws:s3:::aws3-labs-tf-collections/projects/cloudpipe-deploy/*"
        ]
      }
    ]
  }
  )
}

