from security.audit import log_event


class FakeCursor:
    def __init__(self):
        self.executed_query = None
        self.executed_values = None
        self.closed = False

    def execute(self, query, values):
        self.executed_query = query
        self.executed_values = values

    def close(self):
        self.closed = True


class FakeDatabase:
    def __init__(self):
        self.cursor_object = FakeCursor()
        self.committed = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.committed = True


def test_log_event():
    db = FakeDatabase()

    log_event(
        db=db,
        target_type="LOGIN",
        target_id=1,
        ip_address="127.0.0.1",
        user_agent="Test Browser",
        metadata={
            "status": "success"
        }
    )

    cursor = db.cursor_object

    assert "INSERT INTO audit_logs" in cursor.executed_query
    assert cursor.executed_values[0] == "LOGIN"
    assert cursor.executed_values[1] == 1
    assert cursor.executed_values[2] == "127.0.0.1"
    assert cursor.executed_values[3] == "Test Browser"
    assert '"status": "success"' in cursor.executed_values[4]

    assert db.committed is True
    assert cursor.closed is True