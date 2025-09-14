import json
from datetime import datetime, timezone
import resource
from PasswordHasher import PasswordHasher




if __name__ == "__main__":
    json_file = json.load(open("parameters.json", "r"))
    start_time_utc = datetime.now(timezone.utc)
    resource_usage_start = resource.getrusage(resource.RUSAGE_SELF)
    
    hasher = PasswordHasher(algorithm=json_file['algorithm'], **json_file['parameters'])
    salt, generated_hash = hasher.generate_hash(json_file['password_plaintext'])
    end_time_utc = datetime.now(timezone.utc)
    resource_usage_end = resource.getrusage(resource.RUSAGE_SELF)

    memory_rss_mb_start = resource_usage_start.ru_maxrss / 1024
    cpu_user_time_ms_start = resource_usage_start.ru_utime * 1000
    cpu_system_time_ms_start = resource_usage_start.ru_stime * 1000

    cpu_user_time_ms_end = resource_usage_end.ru_utime * 1000
    cpu_system_time_ms_end = resource_usage_end.ru_stime * 1000
    memory_peak_mb_during_hash = resource_usage_end.ru_maxrss / 1024

    cpu_system_time_ms = cpu_system_time_ms_end - cpu_system_time_ms_start
    cpu_user_time_ms = cpu_user_time_ms_end - cpu_user_time_ms_start
    duration_ms = (end_time_utc - start_time_utc).total_seconds() * 1000

    results = json.load(open("results.json", "r"))
    results.update({
        "start_time_utc": start_time_utc.isoformat(),
        "end_time_utc": end_time_utc.isoformat(),
        "duration_ms": duration_ms,
        "cpu_user_time_ms": cpu_user_time_ms,
        "cpu_system_time_ms": cpu_system_time_ms,
        "memory_rss_mb_start": memory_rss_mb_start,
        "memory_peak_mb_during_hash": memory_peak_mb_during_hash
    })
    json.dump(results, open("results.json", "w"))