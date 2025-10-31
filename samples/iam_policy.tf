resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 8
  require_uppercase_characters = false
  require_lowercase_characters = false
  require_numbers = false
  require_symbols = false
}

resource "aws_iam_user_policy" "full_access" {
  name = "insecure-user-policy"
  user = "devuser"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}
