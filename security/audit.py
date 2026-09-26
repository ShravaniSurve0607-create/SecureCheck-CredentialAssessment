import json


def log_event(
    db,
    target_type,
    target_id=None,
    ip_address=None,
    user_agent=None,
    metadata=None
):
    """
    Store a security audit event in the audit_logs table.

    The audit_logs table requires an action value.
    The application already supplies the action inside metadata,
    so it is extracted here and stored in the action column.
    """

    cursor = db.cursor()

    metadata_json = None
    action = target_type

    if metadata is not None:
        metadata_json = json.dumps(metadata)

        if isinstance(metadata, dict):
            action = str(
                metadata.get("action") or target_type
            )

    query = """
        INSERT INTO audit_logs
        (
            target_type,
            target_id,
            ip_address,
            user_agent,
            metadata_json,
            action
        )
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            target_type,
            target_id,
            ip_address,
            user_agent,
            metadata_json,
            action
        )
    )

    db.commit()
    cursor.close()