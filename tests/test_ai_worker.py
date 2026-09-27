"""tools/ai_worker.py heartbeat: fresh while idle or inside a bounded job, stale once a job overruns."""
import time

from tools import ai_worker


def test_heartbeat_stays_fresh_during_a_long_but_bounded_job_and_goes_stale_when_stuck(tmp_path, monkeypatch):
    path = tmp_path / "heartbeat"
    monkeypatch.setattr(ai_worker, "HEARTBEAT", path)
    monkeypatch.setenv("AI_PROVIDER_TIMEOUT_SECONDS", "60")
    heartbeat = ai_worker.Heartbeat()
    assert heartbeat.limit == 3 * 60 + 120

    heartbeat.beat()  # idle
    assert path.exists()
    path.unlink()

    heartbeat.job_started = time.monotonic() - 200  # longer than the probe window, still within the job bound
    heartbeat.beat()
    assert path.exists()
    path.unlink()

    heartbeat.job_started = time.monotonic() - heartbeat.limit - 1  # no bounded job lasts this long
    heartbeat.beat()
    assert not path.exists()
