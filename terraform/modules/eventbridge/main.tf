resource "aws_cloudwatch_event_rule" "ct_tamper" {
  name        = "aegis-cloudtrail-tamper-rule"
  description = "Detect Stop/Delete/Update/Selectors tampering on the CloudTrail baseline"

  event_pattern = jsonencode({
    "source" : ["aws.cloudtrail"],
    "detail-type" : ["AWS API Call via CloudTrail"],
    "detail" : {
      "eventSource" : ["cloudtrail.amazonaws.com"],
      "eventName" : ["StopLogging", "DeleteTrail", "UpdateTrail"],
      "requestParameters" : {
        "name" : [
          "${var.cloudtrail_name}", "${var.cloudtrail_arn}"
        ]
      }
    }
  })

  tags = local.global_tags
}

resource "aws_cloudwatch_event_target" "ct_target" {
  rule      = aws_cloudwatch_event_rule.ct_tamper.name
  target_id = "invoke-aegis-cloudtrail-tamper-shield"
  arn       = var.lambda_cloudtrail_tamper_shield_arn
}

resource "aws_lambda_permission" "allow_events_ct" {
  statement_id  = "AllowFromEventBridgeCT"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_cloudtrail_tamper_shield_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ct_tamper.arn
}
