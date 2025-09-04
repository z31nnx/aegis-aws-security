from datetime import datetime, timezone
import os, json, logging
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

# logging & clients
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_CFG = Config(retries={"max_attempts": 5, "mode": "standard"}, read_timeout=10, connect_timeout=5)
ec2 = boto3.client("ec2", config=_CFG)
sns = boto3.client("sns", config=_CFG)
sts = boto3.client("sts", config=_CFG)
iam = boto3.client("iam", config=_CFG)

#  Env (required/optional)
SNS_HIGH = os.environ["SNS_HIGH"]  # SNS topic ARN
STOP_INSTANCE  = os.getenv("STOP_INSTANCE", "true").lower() in ("1","true","yes","on")
DETACH_PROFILE = os.getenv("DETACH_PROFILE","true").lower() in ("1","true","yes","on")
TAKE_SNAPSHOTS = os.getenv("TAKE_SNAPSHOTS","true").lower() in ("1","true","yes","on")
ISOLATION_SG_ID = os.getenv("ISOLATION_SG_ID","").strip()  # optional pre-created SG id
FINDING_PREFIX  = os.getenv("FINDING_PREFIX","CryptoCurrency:EC2/")

# Tagging (colon style, no env needed)
TAG_STATUS_KEY   = "Aegis:Status"     
TAG_LASTFIX_KEY  = "Aegis:LastFix"
TAG_REASON_KEY   = "Aegis:Reason"
TAG_FINDING_KEY  = "Aegis:FindingType"
TAG_PREV_SGS_KEY = "Aegis:PrevSGs"
TAG_ISO_SG_KEY   = "Aegis:IsolationSG"
TAG_STOPPED_KEY  = "Aegis:Stopped"
TAG_REMEDIATOR   = "Aegis:Remediator"

# Helpers 
def _self():
    try:
        ident = sts.get_caller_identity()
        return {"account": ident.get("Account",""), "caller_arn": ident.get("Arn","")}
    except Exception as e:
        logger.warning("self() failed: %s", e)
        return {"account":"","caller_arn":""}
SELF = _self()

def _arn_region(arn: str) -> str | None:
    try:
        # arn:aws:sns:<region>:<acct>:<name>
        return arn.split(":")[3]
    except Exception:
        return None
def _is_sample(event) -> bool:
    try:
        return bool(
            (event.get("detail") or {})
            .get("service", {})
            .get("additionalInfo", {})
            .get("sample", False)
        )
    except Exception:
        return False

def _utc_ts():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def _tags_to_dict(tag_list):
    return {t["Key"]: t.get("Value","") for t in (tag_list or [])}

def _tag_instance(instance_id: str, kv: dict):
    try:
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key":k,"Value":str(v)[:255]} for k,v in kv.items()])
        return True
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code","UnknownError")
        logger.warning("tag %s failed: %s", instance_id, code)
        return False

def _publish_high(subject, body, attrs=None):
    attrs = attrs or {}
    m = {k: {"DataType":"String","StringValue":str(v)} for k,v in attrs.items()}
    m.update({
        "severity":   {"DataType":"String","StringValue":"HIGH"},
        "service":    {"DataType":"String","StringValue":"guardduty"},
        "automation": {"DataType":"String","StringValue":"aegis-crypto"},
    })
    try:
        resp = sns.publish(TopicArn=SNS_HIGH, Subject=subject[:100], Message=body, MessageAttributes=m)
        logger.info("SNS published. MessageId=%s", resp.get("MessageId"))
    except ClientError as e:
        err = (e.response.get("Error") or {})
        logger.error("sns publish failed: %s - %s", err.get("Code","UnknownError"), err.get("Message",""))
        # allow function to continue; remediation already happened

def _format_email(when, region, instance_id, iso_sg, prev_sgs, snapshots, stopped, errors, event, finding_type):
    header = "[Aegis] Crypto-mining auto-remediation"
    lines = [
        header, "",
        f"Time (UTC): {when}",
        f"Region: {region}",
        f"AWS Account: {SELF.get('account','')}",
        f"Instance: {instance_id}",
        f"Finding: {finding_type or 'manual-test'}",
        "",
        "Actions:",
        f"- Network isolated via SG: {iso_sg or '—'}",
        f"- Previous SGs: {', '.join(prev_sgs) if prev_sgs else '—'}",
        f"- Snapshots: {', '.join(snapshots) if snapshots else '—'}",
        f"- Instance stopped: {str(bool(stopped)).lower()}",
        "",
        "Errors:" if errors else "Errors: None"
    ]
    if errors:
        lines += [f"- {e}" for e in errors]
    try:
        tail = json.dumps(event, separators=(",", ":"))[:1200]
        lines += ["", "Event (truncated):", tail]
    except Exception:
        pass
    return "\n".join(lines)

# Core helpers 
def _extract_instance_id(event) -> str | None:
    try:
        return event["detail"]["resource"]["instanceDetails"]["instanceId"]
    except Exception:
        pass
    # manual test fallback
    for key in ("instanceId","InstanceId","testInstanceId"):
        if key in event:
            return event[key]
        if "detail" in event and key in event["detail"]:
            return event["detail"][key]
    return None

def _guardduty_type(event) -> str:
    return (event.get("detail") or {}).get("type","")

def _describe_instance(iid: str) -> dict | None:
    try:
        r = ec2.describe_instances(InstanceIds=[iid])
        return r["Reservations"][0]["Instances"][0]
    except ClientError as e:
        logger.error("DescribeInstances failed: %s", (e.response.get("Error") or {}).get("Code","Unknown"))
        return None

def _ensure_isolation_sg(vpc_id: str) -> str:
    if ISOLATION_SG_ID:
        return ISOLATION_SG_ID
    # Try to find by name
    try:
        r = ec2.describe_security_groups(
            Filters=[{"Name":"vpc-id","Values":[vpc_id]},
                     {"Name":"group-name","Values":["Aegis-Isolation-SG"]}]
        )
        if r["SecurityGroups"]:
            return r["SecurityGroups"][0]["GroupId"]
    except ClientError:
        pass
    # Create SG with no ingress/egress (revoke default egress)
    sg = ec2.create_security_group(
        GroupName="Aegis-Isolation-SG",
        Description="Quarantine SG: blocks ingress/egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType":"security-group","Tags":[
            {"Key":"Name","Value":"Aegis-Isolation-SG"},
            {"Key":"Aegis:Managed","Value":"true"}
        ]}]
    )
    sg_id = sg["GroupId"]
    try:
        desc = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        egress = desc.get("IpPermissionsEgress", [])
        if egress:
            ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=egress)
    except ClientError as e:
        logger.warning("Revoke egress warn: %s", (e.response.get("Error") or {}).get("Code","Unknown"))
    return sg_id

def _replace_all_enis_with_isolation_sg(instance: dict, isolation_sg_id: str) -> list[str]:
    prev = []
    for ni in instance.get("NetworkInterfaces", []):
        old = [g["GroupId"] for g in ni.get("Groups", [])]
        prev.extend(old)
        ec2.modify_network_interface_attribute(NetworkInterfaceId=ni["NetworkInterfaceId"], Groups=[isolation_sg_id])
    # unique + stable order
    return sorted(set(prev))

def _snapshot_all_vols(instance: dict, reason: str, when: str, finding_type: str, iso_sg: str, incident_id: str) -> list[str]:
    if not TAKE_SNAPSHOTS:
        return []
    snap_ids = []
    root_dev = instance.get("RootDeviceName")
    iid = instance["InstanceId"]

    for bdm in instance.get("BlockDeviceMappings", []):
        ebs = bdm.get("Ebs")
        if not ebs:
            continue
        vol_id = ebs["VolumeId"]
        dev = bdm.get("DeviceName", "")
        is_root = "true" if dev and root_dev and dev == root_dev else "false"

        desc = f"Aegis snapshot - {iid} - {vol_id} ({dev or 'unknown'})"
        tags = [
            {"Key": TAG_REASON_KEY,   "Value": f"Forensics:{reason}"[:255]},
            {"Key": TAG_LASTFIX_KEY,  "Value": when},
            {"Key": TAG_FINDING_KEY,  "Value": finding_type or "manual-test"},
            {"Key": "Aegis:IncidentId",     "Value": incident_id},
            {"Key": "Aegis:SourceInstance", "Value": iid},
            {"Key": "Aegis:SourceVolume",   "Value": vol_id},
            {"Key": "Aegis:DeviceName",     "Value": dev or ""},
            {"Key": "Aegis:RootDevice",     "Value": is_root},
            {"Key": TAG_ISO_SG_KEY,         "Value": iso_sg or ""},
            {"Key": TAG_REMEDIATOR,         "Value": "Lambda-Crypto"},
            {"Key": "Name",                 "Value": f"Aegis Forensics {iid} {dev or vol_id} {when}"},
        ]
        try:
            r = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=desc,
                TagSpecifications=[{"ResourceType":"snapshot","Tags":tags}]
            )
            snap_ids.append(r["SnapshotId"])
        except ClientError as e:
            logger.warning("Snapshot %s failed: %s", vol_id, (e.response.get("Error") or {}).get("Code","Unknown"))
    return snap_ids

def _join_ids(ids, max_len=255):
    s = ",".join(ids)
    if len(s) <= max_len:
        return s
    out=[]; used=0
    for i, sid in enumerate(ids):
        add = (1 if out else 0) + len(sid)
        if used + add > max_len - 8:  # leave room for ",+N"
            return ",".join(out) + f",+{len(ids)-len(out)}"
        out.append(sid); used += add
    return ",".join(out)

def _detach_instance_profile(instance_id: str):
    try:
        r = ec2.describe_iam_instance_profile_associations(Filters=[{"Name":"instance-id","Values":[instance_id]}])
        for assoc in r.get("IamInstanceProfileAssociations", []):
            try:
                ec2.disassociate_iam_instance_profile(AssociationId=assoc["AssociationId"])
            except ClientError as e:
                logger.warning("Disassociate profile warn: %s", (e.response.get("Error") or {}).get("Code","Unknown"))
    except ClientError as e:
        logger.warning("Describe profile assoc warn: %s", (e.response.get("Error") or {}).get("Code","Unknown"))

# ===== Handler =====
def lambda_handler(event, context):
    logger.info("event=%s", json.dumps(event, separators=(",", ":"), default=str))
    target_region = (event.get("region") or os.getenv("AWS_REGION") or "us-east-1")
    sns_region = _arn_region(SNS_HIGH) or target_region

    try:
        globals()["ec2"] = boto3.client("ec2", region_name=target_region, config=_CFG)
        globals()["sns"] = boto3.client("sns", region_name=sns_region,  config=_CFG)
        logger.info("Using regions: ec2=%s, sns=%s", target_region, sns_region)
    except Exception as e:
        logger.warning("regional client init failed: %s", e)

    ftype = _guardduty_type(event)
    if ftype and not ftype.startswith(FINDING_PREFIX):
        logger.info("skip: non-target finding (%s)", ftype)
        return {"skipped":"finding-filter", "type": ftype}

    instance_id = _extract_instance_id(event)
    if not instance_id:
        logger.info("skip: no instance id in event")
        return {"skipped":"no-instance-id"}

    inst = _describe_instance(instance_id)
    if not inst:
        # ALERT-ONLY fallback path (covers SAMPLE findings & missing resources)
        is_sample = _is_sample(event)
        when = _utc_ts()
        region = event.get("region") or os.getenv("AWS_REGION","unknown")
        body = _format_email(
            when, region, instance_id or "—", "", [], [], False,
            ["describe-failed: instance not found (likely SAMPLE or wrong region)"],
            event, ftype or "unknown"
        )
        subject = f"[Aegis/HIGH] Crypto-mining finding (alert-only) → {instance_id or '—'} ({region})"
        _publish_high(subject, body, {"findingType": ftype or "unknown", "alertOnly": True, "sample": is_sample})
        return {
            "ok": False,
            "error": "describe-failed",
            "instance": instance_id,
            "alertOnly": True,
            "sample": is_sample
        }

    region = (inst.get("Placement", {}).get("AvailabilityZone") or "unknown")[:-1] or os.getenv("AWS_REGION","unknown")
    when = _utc_ts()
    incident_id = (event.get("detail") or {}).get("id") or f"manual-{when}"
    tags = _tags_to_dict(inst.get("Tags", []))

    # Idempotency
    if tags.get(TAG_STATUS_KEY, "").lower() in ("quarantined","isolated"):
        logger.info("already quarantined: %s", instance_id)
        return {"ok": True, "note":"already-quarantined", "instance": instance_id}

    reason = "CryptoMiningSuspected"
    actions, errors = [], []

    # Base tags
    _tag_instance(instance_id, {
        TAG_STATUS_KEY: "Quarantined",
        TAG_REASON_KEY: reason,
        TAG_LASTFIX_KEY: when,
        TAG_FINDING_KEY: ftype or "manual-test",
        TAG_REMEDIATOR: "Lambda-GuardDuty-Crypto"
    })

    # Isolation SG
    try:
        iso_sg = _ensure_isolation_sg(inst["VpcId"])
        actions.append(f"IsolationSG:{iso_sg}")
        prev_sgs = _replace_all_enis_with_isolation_sg(inst, iso_sg)
        _tag_instance(instance_id, {TAG_ISO_SG_KEY: iso_sg})
        if prev_sgs:
            _tag_instance(instance_id, {TAG_PREV_SGS_KEY: ",".join(prev_sgs)})
    except Exception as e:
        errors.append(f"isolation:{e}")
        iso_sg, prev_sgs = "", []

    # Forensics
    snapshots = []
    try:
        snapshots = _snapshot_all_vols(inst, reason, when, ftype, iso_sg, incident_id)
        if snapshots:
            actions.append(f"Snapshots:{len(snapshots)}")
    except Exception as e:
        errors.append(f"snapshots:{e}")

    if snapshots:
        _tag_instance(instance_id, {
            "Aegis:Snapshots": _join_ids(snapshots),
            "Aegis:SnapshotCount": str(len(snapshots))
        })

    # Credentials containment
    stopped = False
    if DETACH_PROFILE:
        try:
            _detach_instance_profile(instance_id)
            actions.append("DetachInstanceProfile")
        except Exception as e:
            errors.append(f"detach_profile:{e}")

    # Freeze
    if STOP_INSTANCE:
        try:
            ec2.stop_instances(InstanceIds=[instance_id])
            stopped = True
            _tag_instance(instance_id, {TAG_STOPPED_KEY: "true"})
            actions.append("StopInstance")
        except ClientError as e:
            errors.append(f"stop:{(e.response.get('Error') or {}).get('Code','Unknown')}")
            _tag_instance(instance_id, {TAG_STOPPED_KEY: "false"})

    # Notify
    body = _format_email(when, region, instance_id, iso_sg, prev_sgs, snapshots, stopped, errors, event, ftype)
    subject = f"[Aegis/HIGH] Crypto-mining remediated → {instance_id} ({region})"
    _publish_high(subject, body, {"findingType": ftype or "manual-test", "stopped": stopped})

    return {"ok": (len(errors) == 0), "actions": actions, "errors": errors}
