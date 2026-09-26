import time
from flask import request, g


def start_timer():
    """
    Start measuring request processing time.
    """
    g.request_start_time = time.perf_counter()


def get_request_time():
    """
    Return request processing time in seconds.
    """
    if not hasattr(g, "request_start_time"):
        return 0

    return round(
        time.perf_counter() - g.request_start_time,
        4
    )


def request_info():
    """
    Return basic information about the current request.
    """

    return {
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr
    }