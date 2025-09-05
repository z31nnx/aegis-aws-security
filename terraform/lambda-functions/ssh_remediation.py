import os, json, logging, ipaddress
from datetime import datetime, timezone
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

# Env (required)
# Prefer MEDIUM; gracefully fall back to HIGH so you can roll out without outages.
SNS_MED = os.environ.get("SNS_MED") or os.environ.get("SNS_HIGH")
if not SNS_MED:
    raise RuntimeError("Missing SNS_MED (or SNS_HIGH fallback) environment variable")

ADMIN_PORTS = {
    int(p.strip()) for p in os.getenv("ADMIN_PORTS", "22,3389").split(",") if p.strip()
}

# tagging (constants; no env needed)
TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"
TAG_REASON_KEY = "Aegis:Reason"

def _self():
    try:
        ident = sts.get_caller_identity()
        return {"account": ident.get("Account",""), "caller_arn": ident.get("Arn","")}
    except Exception as e:
        logger.warning("self() failed: %s", e)
        return {"account":"","caller_arn":""}
SELF = _self()

def _utc_ts():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def _tag_sg(group_id: str, reason: str):
    """Attach visual breadcrumbs on the SG for console users."""
    try:
        ec2.create_tags(
            Resources=[group_id],
            Tags=[
                {"Key": TAG_STATUS_KEY,  "Value": "Remediated"},
                {"Key": TAG_LASTFIX_KEY, "Value": _utc_ts()},
                {"Key": TAG_REASON_KEY,  "Value": reason[:255]},
            ],
        )
        return True
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code","UnknownError")
        logger.warning("tagging %s failed: %s", group_id, code)
        return False

def _is_world(cidr: str) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")

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
    actor.update({
        "issuerArn":  issuer.get("arn") or "",
        "issuerName": issuer.get("userName") or "",
        "issuerType": issuer.get("type") or "",
    })
    return actor

def _publish_medium(subject, body, attrs=None):
    """Publish MEDIUM-severity alert to SNS (Aegis SSH/RDP guard)."""
    attrs = attrs or {}
    m = {k: {"DataType":"String","StringValue":str(v)} for k,v in attrs.items()}
    m.update({
        "severity":   {"DataType":"String","StringValue":"MEDIUM"},
        "service":    {"DataType":"String","StringValue":"ec2"},
        "automation": {"DataType":"String","StringValue":"aegis-ssh-guard"},
    })
    try:
        resp = sns.publish(TopicArn=SNS_MED, Subject=subject[:100], Message=body, MessageAttributes=m)
        logger.info(f"SNS published. MessageId={resp.get('MessageId')}")
    except ClientError as e:
        err = (e.response.get("Error") or {})
        code = err.get("Code","UnknownError"); msg = err.get("Message","")
        logger.error(f"sns publish failed: {code} - {msg}")
        raise

def _format_email(evt, when, region, groups, removed_rules, actor, errors, event, src_ip="unknown"):
    header = "[Aegis] SSH/RDP world-open auto-remediation"
    lines = [
        header, "",
        f"Event: {evt}",
        f"Time (UTC): {when}",
        f"Region: {region}",
        f"AWS Account: {SELF.get('account','')}",
        f"Source IP: {src_ip}",
        ""
    ]
    lines += [
        "Actor:",
        f" Type: {actor.get('type') or '—'}",
        f" Account: {actor.get('accountId') or '—'}",
        f" User: {actor.get('userName') or actor.get('principalId') or '—'}",
        f" Arn: {actor.get('arn') or '—'}",
    ]
    if actor.get("issuerArn"):
        lines += [
            "  Issuer (role):",
            f" Name: {actor.get('issuerName') or '—'}",
            f" Type: {actor.get('issuerType') or '—'}",
            f" Arn: {actor.get('issuerArn') or '—'}",
        ]
    lines += ["", "SecurityGroups:"] + [f"- {g}" for g in (groups or ["—"])]

    lines += ["", "Removed rules (admin ports world-open):"]
    if removed_rules:
        for g, rules in removed_rules.items():
            if rules:
                lines.append(f"- {g}:")
                for r in rules:
                    lines.append(f"    • {r}")
    else:
        lines.append("- None")

    lines += ["", "Errors:"] + [f"- {e}" for e in (errors or ["None"])]

    try:
        tail = json.dumps(event)[:1200]
        lines += ["", "Event (truncated):", tail]
    except Exception:
        pass
    return "\n".join(lines)

# core SG logic
def _describe_sg(gid: str) -> dict:
    return ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]

def _perm_includes_port(p: dict, port: int) -> bool:
    proto = p.get("IpProtocol")
    from_p = p.get("FromPort")
    to_p   = p.get("ToPort")

    if proto == "tcp":
        if from_p is not None and to_p is not None:
            return from_p <= port <= to_p
        return False
    return proto == "-1"

def _find_world_admin_permissions(sg_desc: dict):
    """
    Return IpPermissions payload (world-only) across ADMIN_PORTS,
    and pretty strings + per-SG reason tokens (e.g., {'22','3389'}).
    """
    revoke = {"IpPermissions": []}
    pretty = []
    reasons = set()

    for p in sg_desc.get("IpPermissions", []):
        covered = [port for port in ADMIN_PORTS if _perm_includes_port(p, port)]
        if not covered:
            continue

        # IPv4
        for r in p.get("IpRanges", []):
            cidr = r.get("CidrIp")
            if cidr and _is_world(cidr):
                for port in covered:
                    pretty.append(f"IPv4 {cidr} tcp/{port}")
                    revoke["IpPermissions"].append({
                        "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    })
                    reasons.add(str(port))

        # IPv6
        for r6 in p.get("Ipv6Ranges", []):
            cidr6 = r6.get("CidrIpv6")
            if cidr6 and _is_world(cidr6):
                for port in covered:
                    pretty.append(f"IPv6 {cidr6} tcp/{port}")
                    revoke["IpPermissions"].append({
                        "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
                    })
                    reasons.add(str(port))

    return revoke, pretty, reasons


def _revoke(group_id: str, revoke_payload: dict):
    if not revoke_payload["IpPermissions"]:
        return False
    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_payload["IpPermissions"])
        return True
    except ClientError as e:
        code = (e.response.get("Error") or {}).get("Code","")
        if code in ("InvalidPermission.NotFound", "InvalidGroup.NotFound"):
            logger.info("nothing to revoke or SG gone: %s", code)
            return False
        logger.error("revoke failed: %s", code)
        return False

def _extract_group_ids(detail: dict):
    params = detail.get("requestParameters") or {}
    gids = set()
    if detail.get("eventName") == "AuthorizeSecurityGroupIngress":
        if "groupId" in params:
            gids.add(params["groupId"])
        for it in (params.get("groupIdSet", {}) or {}).get("items", []):
            gid = it.get("groupId")
            if gid:
                gids.add(gid)
    if detail.get("eventName") == "ModifySecurityGroupRules":
        gid = params.get("groupId")
        if gid:
            gids.add(gid)
    return list(gids)

# handler
def lambda_handler(event, context):
    detail = event.get("detail") or {}
    evt    = detail.get("eventName", "UnknownEvent")
    region = detail.get("awsRegion", os.getenv("AWS_REGION", "unknown"))
    when   = _utc_ts()
    actor  = _actor_meta(detail)
    src_ip = detail.get("sourceIPAddress", "unknown")

    if evt not in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
        logger.info("skip: not an SG ingress event (%s)", evt)
        return {"skipped":"event-filter", "eventName": evt}

    groups = _extract_group_ids(detail)
    if not groups:
        logger.info("no groupIds in event")
        return {"skipped":"no-group-ids", "eventName": evt}

    removed_map, errors = {}, []

    for gid in groups:
        try:
            sg = _describe_sg(gid)
            revoke_payload, human_rules, reason_ports = _find_world_admin_permissions(sg)
            changed = _revoke(gid, revoke_payload)
            if changed and human_rules:
                removed_map[gid] = human_rules
                # Reason becomes SSH/RDP aware, e.g., "PortsOpen(22,3389)"
                reason_label = (
                    "PortsOpen(" + ",".join(sorted(reason_ports)) + ")"
                    if len(reason_ports) > 1 else
                    ("SSHWorldOpen" if "22" in reason_ports else "RDPWorldOpen")
                )
                _tag_sg(gid, reason=reason_label)
        except Exception as e:
            logger.exception("failed processing %s", gid)
            errors.append(f"{gid}:{e}")

    had_changes = bool(removed_map)
    if had_changes:
        subject = f"[Aegis/MEDIUM] SSH/RDP world-open remediated ({region})"
        body = _format_email(evt, when, region, groups, removed_map, actor, errors, event, src_ip)
        _publish_medium(subject, body, {"eventName": evt, "removed": True})
    else:
        logger.info("No world-open admin-port rules to remediate; email suppressed.")

    return {"ok": (not errors), "removed": removed_map, "errors": errors}
