# AWS CloudWatch Logs source (optional)

Analyse logs that already live in CloudWatch (EC2 with the CloudWatch agent, ECS, Lambda) without exporting
them first. The tool is **read-only**: it never creates, changes or deletes anything in AWS.

## Install

```bash
pip install ".[aws]"            # adds boto3
# Docker: docker build --build-arg WITH_AWS=true -t incident-analyzer:aws .
```

## Use

```bash
incident-analyzer analyze --cloudwatch-group /aws/ecs/checkout-api --since 1h
incident-analyzer analyze --cloudwatch-group /var/log/myapp --since 2026-10-31T09:00:00Z --filter-pattern ERROR \
    --aws-region ap-south-1 --aws-profile prod-readonly
# You can combine a CloudWatch group with local files in the same run
incident-analyzer analyze local.log --cloudwatch-group /aws/lambda/worker --since 30m --format json -o report.json
```

* `--since`: `30m`, `2h`, `1d`, or an ISO-8601 timestamp (naive means UTC).
* `--filter-pattern`: a CloudWatch filter pattern that narrows events *server-side* (cheaper and faster).
* Default service name = the last segment of the log group (`/aws/ecs/checkout-api` becomes `checkout-api`);
  override with `--default-service`.
* Each event's message is parsed with the normal parsers. If a line has no timestamp of its own, the
  CloudWatch ingestion time is used. Multi-line messages, and traces split across consecutive events, are kept together.
* At most 50,000 events are fetched per run; if there is more, a warning says so (narrow `--since` or add a filter).

## Credentials

The standard AWS chain: environment variables, `~/.aws` profile or SSO, or the **instance role** on EC2/ECS.
On EC2, attach an instance profile with the policy below and no keys are needed at all. **Do not** put
long-lived access keys in this project's files.

## Minimum IAM permission

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOneAppLogGroup",
      "Effect": "Allow",
      "Action": "logs:FilterLogEvents",
      "Resource": "arn:aws:logs:<region>:<account-id>:log-group:/aws/ecs/checkout-api:*"
    }
  ]
}
```

Replace the region, account id and log group. Grant one resource per group you analyse. Nothing else is needed.

## Cost and limits

* CloudWatch Logs charges for data scanned and API usage in some configurations; check the current
  pricing for your region. `--filter-pattern` and a tight `--since` keep it small.
* `FilterLogEvents` is rate-limited. The client retries with boto3's *standard* retry mode (5 attempts);
  a persistent throttle gives an actionable error message.

## Errors you may see

| Message | Meaning | Fix |
|---|---|---|
| `boto3 is not installed` | missing extra | `pip install ".[aws]"` |
| `log group not found (check the name and region)` | wrong name or region | verify with `aws logs describe-log-groups` |
| `access denied: the credentials need logs:FilterLogEvents` | IAM | attach the policy above |
| `AWS credentials are expired or invalid` | SSO/session expired | `aws sso login` or refresh the profile |
| `throttled ... after several retries` | rate limit | narrow `--since`, add `--filter-pattern`, retry later |
| warning: `CloudWatch fetch stopped after 50000 events` | result capped | narrow the window or filter |

## Testing

`tests/test_cloudwatch.py` uses a fake client that mimics pagination (`nextToken`) and error codes, so the
logic is tested without AWS. There is one extra test using real `botocore` exception types that runs when
the `[aws]` extra is installed (CI installs it).
