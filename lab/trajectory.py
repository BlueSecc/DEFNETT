"""Evidence-backed event grouping; links are correlations, not causal claims."""
from datetime import datetime, timezone
import json
import uuid

MAX_CORRELATION_GAP_SECONDS = 600
MEDIUM_CORRELATION_GAP_SECONDS = 60


def _parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def assign(connection, event, event_id, timestamp):
    """Assign only when same-host/path evidence has a bounded temporal/hash link."""
    current_time = _parse_timestamp(timestamp)
    if current_time is None:
        raise ValueError("invalid_event_timestamp")
    rows = connection.execute(
        """SELECT e.id, e.trajectory_id, e.timestamp, e.event_type, e.canonical_json,
                  e.old_hash, e.new_hash,
                  (SELECT MIN(started.timestamp) FROM events AS started
                   WHERE started.trajectory_id = e.trajectory_id) AS trajectory_started
           FROM events AS e
           WHERE e.host_id = ? AND e.path = ? AND e.trajectory_id LIKE 'traj-%'
           ORDER BY e.rowid DESC LIMIT 100""",
        (event.get("host_id"), event.get("path")),
    ).fetchall()
    candidates = []
    for row in rows:
        prior_time = _parse_timestamp(row["timestamp"])
        if prior_time is None:
            continue
        gap = abs((current_time - prior_time).total_seconds())
        if gap > MAX_CORRELATION_GAP_SECONDS:
            continue
        trajectory_start = _parse_timestamp(row["trajectory_started"])
        if trajectory_start is None or abs((current_time - trajectory_start).total_seconds()) > MAX_CORRELATION_GAP_SECONDS:
            continue
        hash_continuity = bool(
            (row["new_hash"] and event.get("old_hash") and row["new_hash"] == event.get("old_hash"))
            or (event.get("new_hash") and row["old_hash"] and event.get("new_hash") == row["old_hash"])
        )
        if event.get("event_type") == "OT_MODBUS_TRANSACTION":
            if row["event_type"] != "OT_MODBUS_TRANSACTION" or gap > MEDIUM_CORRELATION_GAP_SECONDS:
                continue
            try:
                prior_event = json.loads(row["canonical_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                continue
            same_identity = all((
                prior_event.get("device_id") == event.get("device_id"),
                prior_event.get("source_ip") == event.get("source_ip"),
                prior_event.get("unit_id") == event.get("unit_id"),
                prior_event.get("register_start") == event.get("register_start"),
            ))
            policy_denial = "DENY" in {prior_event.get("policy_decision"), event.get("policy_decision")}
            if not (same_identity and policy_denial):
                continue
            confidence = 0.65
            relation = "MEDIUM_CORRELATION"
            reason = "same_device_source_unit_register_with_policy_denial"
        elif row["event_type"] == "OT_MODBUS_TRANSACTION":
            continue
        elif hash_continuity:
            confidence = 0.9
            relation = "STRONG_CORRELATION"
            reason = "same_host_path_hash_continuity"
        elif gap <= MEDIUM_CORRELATION_GAP_SECONDS:
            confidence = 0.6
            relation = "MEDIUM_CORRELATION"
            reason = "same_host_path_within_60_seconds_no_hash_chain"
        else:
            continue
        candidates.append((confidence, gap, row, relation, reason, prior_time))

    if not candidates:
        return f"traj-{uuid.uuid4()}", []
    confidence, _, prior, relation, reason, prior_time = sorted(
        candidates, key=lambda item: (-item[0], item[1])
    )[0]
    edge = {
        "source_event_id": prior["id"] if prior_time <= current_time else event_id,
        "target_event_id": event_id if prior_time <= current_time else prior["id"],
        "relation": relation,
        "confidence": confidence,
        "reason": reason,
    }
    return prior["trajectory_id"], [edge]


def list_trajectories(connection, limit=100):
    rows = connection.execute(
        """SELECT trajectory_id, host_id, MIN(timestamp) AS started_at,
                  MAX(timestamp) AS updated_at, COUNT(*) AS event_count
           FROM events WHERE trajectory_id LIKE 'traj-%'
           GROUP BY trajectory_id, host_id ORDER BY MAX(timestamp) DESC LIMIT ?""",
        (max(1, min(int(limit), 500)),),
    ).fetchall()
    result = []
    for row in rows:
        events = connection.execute(
            """SELECT id, timestamp, event_type, path, integrity_hash
               FROM events WHERE trajectory_id = ? ORDER BY timestamp, rowid""",
            (row["trajectory_id"],),
        ).fetchall()
        edges = connection.execute(
            """SELECT source_event_id, target_event_id, relation, confidence, reason
               FROM event_relationships WHERE source_event_id IN
                 (SELECT id FROM events WHERE trajectory_id = ?)
               AND target_event_id IN
                 (SELECT id FROM events WHERE trajectory_id = ?) ORDER BY id""",
            (row["trajectory_id"], row["trajectory_id"]),
        ).fetchall()
        result.append({**dict(row), "events": [dict(item) for item in events],
                       "relationships": [dict(item) for item in edges]})
    return result
