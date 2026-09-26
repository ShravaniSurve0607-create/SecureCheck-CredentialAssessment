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

    The function uses the existing audit_logs table structure:
    target_type, target_id, ip_address, user_agent,
    metadata_json, created_at.
    """

    cursor = db.cursor()

    metadata_json = None

    if metadata is not None:
        metadata_json = json.dumps(metadata)

    query = """
        INSERT INTO audit_logs
        (
            target_type,
            target_id,
            ip_address,
            user_agent,
            metadata_json
        )
        VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            target_type,
            target_id,
            ip_address,
            user_agent,
            metadata_json
        )
    )

    db.commit()
    cursor.close()