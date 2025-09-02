resource "aws_cloudwatch_event_rule" "lambda_cloudtrail_tamper_shield_rule" {
  name        = "${var.name_prefix}-${var.lambda_cloudtrail_tamper_shield_function_name}"
  description = "Detect Stop/Delete/Update/ tampering on the CloudTrail baseline"

  event_pattern = jsonencode({
    "source" : ["aws.cloudtrail"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["cloudtrail.amazonaws.com"]
      "eventName" : ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_cloudtrail_tamper_shield_rule_target" {
  rule      = aws_cloudwatch_event_rule.lambda_cloudtrail_tamper_shield_rule.name
  target_id = "invoke-aegis-cloudtrail-tamper-shield"
  arn       = var.lambda_cloudtrail_tamper_shield_function_arn
}

resource "aws_lambda_permission" "lambda_cloudtrail_tamper_shield_rule_allow_events" {
  statement_id  = "AllowFromEventBridgeCT"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_cloudtrail_tamper_shield_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_cloudtrail_tamper_shield_rule.arn
}

resource "aws_cloudwatch_event_rule" "lambda_ssh_remediation_rule" {
  name        = "${var.name_prefix}-${var.lambda_ssh_remediation_function_name}"
  description = "Trigger on AuthorizeSecurityGroupIngress"
  event_pattern = jsonencode({
    "source" : ["aws.ec2"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["ec2.amazonaws.com"],
      "eventName" : ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_ssh_remediation_rule_target" {
  rule      = aws_cloudwatch_event_rule.lambda_ssh_remediation_rule.name
  target_id = "invoke-aegis-ssh-remediation"
  arn       = var.lambda_ssh_remediation_function_arn
}

resource "aws_lambda_permission" "lambda_ssh_remediation_permissions" {
  statement_id  = "AllowFromEventBridgeSSH"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_ssh_remediation_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_ssh_remediation_rule.arn
}

resource "aws_cloudwatch_event_rule" "lambda_crypto_quarantine_rule" {
  name        = "${var.name_prefix}-${var.lambda_crypto_quarantine_function_name}"
  description = "GuardDuty CryptoCurrency EC2 findings → Aegis crypto quarantine"
  event_pattern = jsonencode({
    "source" : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"],
    "detail" : {
      "type" : [{ "prefix" : "CryptoCurrency:EC2/*" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_crypto_quarantine_rule_target" {
  rule      = aws_cloudwatch_event_rule.lambda_crypto_quarantine_rule.name
  target_id = "crypto-quarantine"
  arn       = var.lambda_crypto_quarantine_function_arn
}

resource "aws_lambda_permission" "lambda_crypto_quarantine_allow_invoke" {
  statement_id  = "AllowEventBridgeGuardDutyInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_crypto_quarantine_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_crypto_quarantine_rule.arn
}
