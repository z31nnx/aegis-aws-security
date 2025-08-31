import os, json, time, datetime, logging
import uuid, gzip
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_CFG = Config(retries={"max_attempts": 5, "mode": "standard"}, read_timeout=10, connect_timeout=5)
ct  = boto3.client("cloudtrail", config=_CFG)
sns = boto3.client("sns",        config=_CFG)
sts = boto3.client("sts",        config=_CFG)
s3 = boto3.client("s3", config=_CFG)

def _b(v, default=False):
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")

def _j(v):
    if not v:
        return None
    try:
        return json.loads(v)
    except Exception:
        return None

# env baseline (Terraform)
TRAIL_NAME   = os.environ["TRAIL_NAME"]
S3_BUCKET    = os.environ["LOG_BUCKET"]
S3_PREFIX    = os.getenv("LOG_PREFIX", "").strip("/")
KMS_KEY_ID   = os.getenv("KMS_KEY_ID", "")
MULTI_REGION = _b(os.getenv("MULTI_REGION", "true"))
INCLUDE_GSE  = _b(os.getenv("INCLUDE_GLOBAL", "true"))
VALIDATION   = _b(os.getenv("LOG_VALIDATION", "true"))
IS_ORG       = _b(os.getenv("ORG_TRAIL", "false"))

BASELINE_TAGS = _j(os.getenv("BASELINE_TAGS_JSON", "{}")) or {}
EVENT_SELECTORS   = _j(os.getenv("EVENT_SELECTORS_JSON"))
INSIGHT_SELECTORS = _j(os.getenv("INSIGHT_SELECTORS_JSON"))
EVENT_DUMP_BUCKET   = os.getenv("EVENT_DUMP_BUCKET", "")            
EVENT_DUMP_PREFIX   = os.getenv("EVENT_DUMP_PREFIX", "aegis/events/cloudtrail")
EVENT_DUMP_KMS_ARN  = os.getenv("EVENT_DUMP_KMS_ARN", "")           # optional KMS for dumps
PRESIGN_TTL_SECS    = int(os.getenv("PRESIGN_TTL_SECS", "3600"))    # 1h link
TRUNCATE_LEN        = int(os.getenv("TRUNCATE_LEN", "1200"))        # email snippet length
INCLUDE_EVENT_SNIP  = os.getenv("INCLUDE_EVENT_SNIPPET", "1").lower() in ("1","true","yes","on")


SNS_HIGH       = os.environ["SNS_HIGH"]
ALLOWED_EVENTS = {e.strip() for e in os.getenv(
    "ALLOWED_EVENTS", "StopLogging,DeleteTrail,UpdateTrail,PutEventSelectors"
).split(",") if e.strip()}

# self detect (no envs needed; envs override if present) 
def _resolve_self():
    role_name_env = os.getenv("SELF_ROLE_NAME", "")
    role_arn_env  = os.getenv("SELF_ROLE_ARN", "")
    try:
        ident   = sts.get_caller_identity()
        acct    = ident.get("Account", "")
        sts_arn = ident.get("Arn", "")  
        role_name = ""
        if ":assumed-role/" in sts_arn:
            role_name = sts_arn.split(":assumed-role/")[-1].split("/")[0]
        elif "/assumed-role/" in sts_arn:
            role_name = sts_arn.split("/assumed-role/")[-1].split("/")[0]
        role_arn = f"arn:aws:iam::{acct}:role/{role_name}" if role_name else ""
        return {"account": acct, "sts_arn": sts_arn,
                "role_name": role_name_env or role_name,
                "role_arn":  role_arn_env  or role_arn}
    except Exception as e:
        logger.warning("self-detect failed: %s", e)
        return {"account":"", "sts_arn":"", "role_name": role_name_env, "role_arn": role_arn_env}

def _dump_event_to_s3(event, when, region, evt):
    if not EVENT_DUMP_BUCKET:
        return None
    safe_when = when.replace(":", "-")
    key = f"{EVENT_DUMP_PREFIX}/{region}/{evt}/{safe_when}-{uuid.uuid4().hex}.json.gz"
    body = gzip.compress(json.dumps(event, separators=(",", ":")).encode("utf-8"))

    extra = {"ServerSideEncryption": "AES256"}
    if EVENT_DUMP_KMS_ARN:
        extra = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": EVENT_DUMP_KMS_ARN}

    s3.put_object(Bucket=EVENT_DUMP_BUCKET, Key=key, Body=body,
                  ContentType="application/json", ContentEncoding="gzip", **extra)

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": EVENT_DUMP_BUCKET, "Key": key},
        ExpiresIn=PRESIGN_TTL_SECS,
    )
    return {"bucket": EVENT_DUMP_BUCKET, "key": key, "url": url}

def _trail_arn(name: str):
    try:
        resp = ct.describe_trails(trailNameList=[name], includeShadowTrails=False)
        for t in resp.get("trailList", []):
            if t.get("Name") == name:
                return t.get("TrailARN")
    except ClientError:
        pass
    return None

def _get_trail_tags(arn: str) -> dict:
    try:
        resp = ct.list_tags(ResourceIdList=[arn])
        for item in resp.get("ResourceTagList", []):
            if item.get("ResourceId") == arn:
                return {t["Key"]: t.get("Value","") for t in item.get("TagsList", [])}
    except ClientError as e:
        logger.warning("list trail tags failed: %s", (e.response.get("Error") or {}).get("Code"))
    return {}

def ensure_trail_tags(trail_name: str, dynamic: dict):
    """
    Add baseline tags only if missing; always update dynamic tags.
    Never removes any tags. Idempotent.
    """
    arn = _trail_arn(trail_name)
    if not arn:
        return
    existing = _get_trail_tags(arn)

    desired = {}
    for k, v in (BASELINE_TAGS or {}).items():
        if existing.get(k) is None:
            desired[k] = str(v)

    for k, v in (dynamic or {}).items():
        if existing.get(k) != str(v):
            desired[k] = str(v)

    if desired:
        try:
            ct.add_tags(ResourceId=arn, TagsList=[{"Key": k, "Value": v} for k, v in desired.items()])
        except ClientError as e:
            logger.warning("add trail tags failed: %s", (e.response.get("Error") or {}).get("Code"))
            logger.info("tagging trail %s with %s", TRAIL_NAME, desired)
            

SELF = _resolve_self()

def _actor_strings(detail: dict):
    ui = detail.get("userIdentity") or {}
    arn = ui.get("arn", "")
    sess = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
    issuer_arn  = sess.get("arn", "")
    issuer_name = sess.get("userName", "")
    return arn, issuer_arn, issuer_name

def is_self_actor(detail: dict) -> bool:
    actor_arn, issuer_arn, issuer_name = _actor_strings(detail)
    acct = SELF.get("account", "")
    rn   = SELF.get("role_name") or ""
    ra   = SELF.get("role_arn")  or ""
    # Strict matches: exact issuer role ARN or STS assumed-role prefix for role
    if ra and issuer_arn == ra:
        return True
    if rn and actor_arn.startswith(f"arn:aws:sts::{acct}:assumed-role/{rn}/"):
        return True
    return False

# Trail targeting: accept name or ARN; handle missing parameters safely 
def _expected_trail_ids(region, account, name):
    return {name, f"arn:aws:cloudtrail:{region}:{account}:trail/{name}"}

def _event_trail(detail):
    rp = detail.get("requestParameters") or {}
    return (
        rp.get("name")
        or rp.get("trailName")
        or rp.get("trailArn")
        or rp.get("trailARN")
        or ""
    )

def _likely_ours_when_missing():
    try:
        resp = ct.describe_trails(trailNameList=[TRAIL_NAME], includeShadowTrails=False)
        trails = resp.get("trailList", [])
        return any(t.get("Name") == TRAIL_NAME for t in trails)
    except ClientError:
        return False

def is_for_our_trail(detail):
    region  = detail.get("awsRegion", os.getenv("AWS_REGION", ""))
    account = SELF.get("account", "")
    target  = _event_trail(detail)
    if not target:
        return _likely_ours_when_missing()
    ids = _expected_trail_ids(region, account, TRAIL_NAME)
    return (target in ids) or target.endswith(f":trail/{TRAIL_NAME}")

def _sleep_chain(delays=(0.8, 1.5, 3.0)):
    for d in delays:
        time.sleep(d)
        yield

def create_or_update_trail():
    args = {
        "Name": TRAIL_NAME,
        "S3BucketName": S3_BUCKET,
        "IsMultiRegionTrail": MULTI_REGION,
        "IncludeGlobalServiceEvents": INCLUDE_GSE,
        "EnableLogFileValidation": VALIDATION,
    }
    if S3_PREFIX: args["S3KeyPrefix"] = S3_PREFIX
    if KMS_KEY_ID: args["KmsKeyId"]   = KMS_KEY_ID
    if IS_ORG:     args["IsOrganizationTrail"] = True

    try:
        ct.update_trail(**args)
        return "UpdateTrail"
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "")
        if code not in ("TrailNotFoundException", "ResourceNotFoundException", "InvalidTrailNameException"):
            raise

    last_err = None
    for _ in _sleep_chain():
        try:
            ct.create_trail(**args)
            return "CreateTrail"
        except ClientError as e:
            last_err = (e.response.get("Error") or {}).get("Code", "UnknownError")
    raise ClientError({"Error": {"Code": last_err}}, "CreateTrail")

def ensure_selectors():
    did = []
    if EVENT_SELECTORS is not None:
        ct.put_event_selectors(TrailName=TRAIL_NAME, EventSelectors=EVENT_SELECTORS)
        did.append("PutEventSelectors")
    if INSIGHT_SELECTORS is not None:
        ct.put_insight_selectors(TrailName=TRAIL_NAME, InsightSelectors=INSIGHT_SELECTORS)
        did.append("PutInsightSelectors")
    return did

def ensure_logging():
    for _ in range(4):
        try:
            st = ct.get_trail_status(Name=TRAIL_NAME)
            if not bool(st.get("IsLogging", False)):
                ct.start_logging(Name=TRAIL_NAME)
            st2 = ct.get_trail_status(Name=TRAIL_NAME)
            if bool(st2.get("IsLogging", False)):
                return True
        except ClientError:
            pass
        time.sleep(1.0)
    return False

def publish_high(subject, body, attrs=None):
    m = {k: {"DataType":"String","StringValue":str(v)} for k,v in (attrs or {}).items()}
    m.update({
        "severity":   {"DataType":"String","StringValue":"HIGH"},
        "service":    {"DataType":"String","StringValue":"cloudtrail"},
        "automation": {"DataType":"String","StringValue":"ct-guard"},
    })
    try:
        sns.publish(TopicArn=SNS_HIGH, Subject=subject[:100], Message=body, MessageAttributes=m)
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code","UnknownError")
        logger.error("sns publish failed: %s", code)

def _actor_meta(detail: dict):
    ui = detail.get("userIdentity") or {}
    actor = {
        "type":        ui.get("type") or "unknown",
        "accountId":   ui.get("accountId") or "",
        "arn":         ui.get("arn") or "",
        "userName":    ui.get("userName") or ui.get("principalId") or "",
        "principalId": ui.get("principalId") or "",
    }
    issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {})
    if issuer:
        actor.update({
            "issuerArn":  issuer.get("arn") or "",
            "issuerName": issuer.get("userName") or "",
            "issuerType": issuer.get("type") or "",
        })
    else:
        actor.update({"issuerArn":"", "issuerName":"", "issuerType":""})
    return actor

def _format_email(evt, when, region, trail, src_ip, actor_meta, actions, errors, event_snippet=None, dump_url=None):
    header = "[Aegis] CloudTrail tamper auto-remediation"
    lines = [
        header, "",
        f"Event: {evt}",
        f"Time (UTC): {when}",
        f"Region: {region}",
        f"Trail: {trail}",
        f"Source IP: {src_ip}",
        "",
        "Actor:",
        f"Type: {actor_meta.get('type') or '—'}",
        f"Account: {actor_meta.get('accountId') or '—'}",
        f"User/prin: {actor_meta.get('userName') or actor_meta.get('principalId') or '—'}",
        f"Arn: {actor_meta.get('arn') or '—'}",
    ]
    if actor_meta.get("issuerArn"):
        lines += [
            "",
            "issuer (role):",
            f"Name: {actor_meta.get('issuerName') or '—'}",
            f"Type: {actor_meta.get('issuerType') or '—'}",
            f"Arn: {actor_meta.get('issuerArn') or '—'}",
        ]

    lines += ["", "Actions:"] + [f"- {a}" for a in (actions or ["No change required"])]
    lines += ["", "Errors:"]  + [f"- {e}" for e in (errors or ["None"])]

    if dump_url:
        lines += ["", f"Full event (pre-signed): {dump_url} (expires in {PRESIGN_TTL_SECS}s)"]

    if INCLUDE_EVENT_SNIP and TRUNCATE_LEN > 0:
        try:
            tail = json.dumps(event_snippet, separators=(",", ":"))[:TRUNCATE_LEN]
            lines += ["", "Event (snippet):", tail]
        except Exception:
            pass

    return "\n".join(lines)

def lambda_handler(event, context):
    detail = event.get("detail") or {}
    evt    = detail.get("eventName", "UnknownEvent")
    src_ip = detail.get("sourceIPAddress", "unknown")
    region = detail.get("awsRegion", os.getenv("AWS_REGION", "unknown"))
    when = (detail.get("eventTime") or datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z")

    if evt not in ALLOWED_EVENTS:
        logger.info("skip: event %s not in ALLOWED_EVENTS", evt)
        return {"skipped": "not-allowed-event", "eventName": evt}

    # Loop guard
    if is_self_actor(detail):
        logger.info("skip: self-actor for %s", evt)
        return {"skipped": "self-actor", "eventName": evt}

    # Trail guard (accept name or ARN; handle missing cautiously)
    if not is_for_our_trail(detail):
        logger.info("skip: other-trail (%s)", _event_trail(detail))
        return {"skipped": "other-trail", "eventName": evt}

    logger.info("tamper detected: %s on trail %s (%s)", evt, TRAIL_NAME, region)

    actions, errors = [], []

    try:
        actions.append(create_or_update_trail())
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "UnknownError")
        errors.append(f"CreateOrUpdate:{code}")
        logger.exception("create/update failed: %s", code)

    try:
        actions += ensure_selectors()
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "UnknownError")
        errors.append(f"Selectors:{code}")
        logger.exception("selectors failed: %s", code)

    if ensure_logging():
        actions.append("StartLoggingEnsured")
    else:
        errors.append("StartLoggingFailed")

    actor = _actor_meta(detail)
    subject = f"[Aegis/HIGH] {evt} → auto-remediation ({TRAIL_NAME} | {region})"[:100]

    dump = None
    try:
        dump = _dump_event_to_s3(event, when, region, evt)
    except Exception as e:
        logger.warning("event dump failed: %s", e)

    body = _format_email(
        evt, when, region, TRAIL_NAME, src_ip, actor, actions, errors,
        event_snippet=event,
        dump_url=(dump or {}).get("url")
    )

    publish_high(subject, body, {"eventName": evt, "actor": actor.get("arn", "")})

    dynamic = {
    "Aegis:Status": "Remediated" if not errors else "Error",
    "Aegis:Reason": f"Tamper:{evt}",
    "Aegis:LastFix": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    "Aegis:Remediator": "Lambda-CT-Tamper",
    }
    ensure_trail_tags(TRAIL_NAME, dynamic)

    return {"ok": len(errors) == 0, "actions": actions, "errors": errors}
