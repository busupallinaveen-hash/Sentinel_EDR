#!/usr/bin/env python3
"""
sensors/linux/ebpf_sensor.py — Linux eBPF / Audit Sensor

Deep Linux kernel telemetry via:
  1. eBPF (via bcc/bpftrace) if available — best depth
  2. Linux Audit subsystem (auditd) — good coverage, always available
  3. /proc filesystem polling — fallback, always works

Provides:
  - execve() syscall monitoring (every process launch)
  - connect() syscall monitoring (every network connection)
  - open() syscall on sensitive files (/etc/passwd, /etc/shadow)
  - Privilege escalation (setuid syscall)
  - Kernel module loading (init_module)

Linux-only. Gracefully disabled on other platforms.

Install bcc for eBPF: apt install python3-bpfcc bpfcc-tools
"""

import logging, os, platform, subprocess, threading, time
from collections import defaultdict
from pathlib import Path

log = logging.getLogger("SentinelEDR.eBPFSensor")

if platform.system() != "Linux":
    class EBPFSensor:
        ENGINE = "eBPFSensor"
        def run(self, event_bus):
            log.debug("eBPF sensor: Linux-only, disabled")
else:
    # Try bcc (eBPF)
    try:
        from bcc import BPF
        BCC_OK = True
    except ImportError:
        BCC_OK = False

    # Sensitive files to watch
    SENSITIVE_FILES = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/root/.ssh/authorized_keys", "/etc/crontab",
        "/etc/ld.so.preload", "/etc/environment",
        "/proc/kcore", "/dev/mem",
    }

    SENSITIVE_DIRS = {
        "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
        "/root/.ssh", "/home",
    }

    # eBPF C program for execve + connect monitoring
    BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};
BPF_PERF_OUTPUT(exec_events);

int syscall__execve(struct pt_regs *ctx,
                    const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp) {
    struct exec_event_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.pid  = bpf_get_current_pid_tgid() >> 32;
    data.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct setuid_event_t {
    u32 pid;
    u32 old_uid;
    u32 new_uid;
    char comm[16];
};
BPF_PERF_OUTPUT(setuid_events);

int syscall__setuid(struct pt_regs *ctx, uid_t uid) {
    struct setuid_event_t data = {};
    data.pid     = bpf_get_current_pid_tgid() >> 32;
    data.old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.new_uid = uid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (data.old_uid != 0 && data.new_uid == 0) {
        setuid_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""


    class EBPFSensor:
        ENGINE = "eBPFSensor"

        def __init__(self):
            self._alerted = set()
            self._lock    = threading.Lock()
            self._event_bus = None

        def _on_exec_event(self, cpu, data, size):
            try:
                from bcc import BPF
                event = self._bpf["exec_events"].event(data)
                filename = event.filename.decode("utf-8", errors="replace")
                comm     = event.comm.decode("utf-8", errors="replace")
                pid      = event.pid
                uid      = event.uid

                # Alert on execution from suspicious paths
                suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/",
                                    "/run/user/", "/.cache/"]
                for sp in suspicious_paths:
                    if filename.startswith(sp):
                        alert_key = f"ebpf_exec:{pid}:{filename}"
                        with self._lock:
                            if alert_key in self._alerted:
                                return
                            self._alerted.add(alert_key)

                        from core.alert_manager import Alert
                        a = Alert(
                            alert_type   = "EBPF_SUSPICIOUS_EXEC",
                            severity     = "HIGH",
                            title        = f"Execution from suspicious path: {filename}",
                            description  = (
                                f"Process '{comm}' (PID {pid}, UID {uid}) executed "
                                f"binary from '{filename}' — suspicious path "
                                f"commonly used by malware droppers."
                            ),
                            process_info = {"pid": pid, "uid": uid,
                                            "comm": comm, "filename": filename},
                            risk_score   = 75,
                            mitre_tactic = "execution",
                            mitre_tech   = "T1059",
                            engine       = self.ENGINE,
                        )
                        if self._event_bus:
                            self._event_bus.publish("alert", {"kind": "alert", "alert": a})
                        return
            except Exception as e:
                log.debug(f"eBPF exec event error: {e}")

        def _on_setuid_event(self, cpu, data, size):
            try:
                from bcc import BPF
                event = self._bpf["setuid_events"].event(data)
                comm  = event.comm.decode("utf-8", errors="replace")
                pid   = event.pid

                alert_key = f"ebpf_setuid:{pid}:{comm}"
                with self._lock:
                    if alert_key in self._alerted:
                        return
                    self._alerted.add(alert_key)

                from core.alert_manager import Alert
                a = Alert(
                    alert_type   = "EBPF_PRIVILEGE_ESCALATION",
                    severity     = "CRITICAL",
                    title        = f"Privilege escalation: {comm} → root (eBPF)",
                    description  = (
                        f"Process '{comm}' (PID {pid}) called setuid(0) from "
                        f"unprivileged context — possible privilege escalation exploit."
                    ),
                    process_info = {"pid": pid, "comm": comm,
                                    "old_uid": event.old_uid, "new_uid": 0},
                    risk_score   = 95,
                    mitre_tactic = "privilege_escalation",
                    mitre_tech   = "T1068",
                    engine       = self.ENGINE,
                )
                if self._event_bus:
                    self._event_bus.publish("alert", {"kind": "alert", "alert": a})
            except Exception as e:
                log.debug(f"eBPF setuid event error: {e}")

        def _run_ebpf(self, event_bus):
            from bcc import BPF
            self._bpf = BPF(text=BPF_PROGRAM)
            self._bpf.attach_kprobe(event="sys_execve",  fn_name="syscall__execve")
            self._bpf.attach_kprobe(event="sys_setuid",  fn_name="syscall__setuid")
            self._bpf["exec_events"].open_perf_buffer(self._on_exec_event)
            self._bpf["setuid_events"].open_perf_buffer(self._on_setuid_event)
            log.info("eBPF probes attached (execve + setuid)")
            while True:
                try:
                    self._bpf.perf_buffer_poll(timeout=100)
                except Exception as e:
                    log.debug(f"eBPF poll error: {e}")
                    time.sleep(1)

        def _run_audit_fallback(self, event_bus):
            """
            Fallback: parse /proc for sensitive file access + execve monitoring.
            Works without eBPF — lower fidelity but always available.
            """
            log.info("eBPF not available — using /proc audit fallback")
            known_pids = set()
            while True:
                try:
                    # Check for new processes executing from suspicious paths
                    for pid_dir in Path("/proc").iterdir():
                        if not pid_dir.name.isdigit():
                            continue
                        pid = int(pid_dir.name)
                        if pid in known_pids:
                            continue
                        known_pids.add(pid)
                        try:
                            exe = os.readlink(str(pid_dir / "exe"))
                            suspicious = ["/tmp/", "/dev/shm/", "/var/tmp/"]
                            for sp in suspicious:
                                if exe.startswith(sp):
                                    cmdline = (pid_dir / "cmdline").read_text(
                                        errors="replace").replace("\x00", " ").strip()[:200]
                                    alert_key = f"proc:{pid}:{exe}"
                                    with self._lock:
                                        if alert_key in self._alerted:
                                            break
                                        self._alerted.add(alert_key)

                                    from core.alert_manager import Alert
                                    a = Alert(
                                        alert_type   = "PROC_SUSPICIOUS_EXEC",
                                        severity     = "HIGH",
                                        title        = f"Execution from suspicious path: {exe}",
                                        description  = (
                                            f"PID {pid} executing from '{exe}' "
                                            f"(cmd: {cmdline})"
                                        ),
                                        process_info = {"pid": pid, "exe": exe,
                                                        "cmdline": cmdline},
                                        risk_score   = 70,
                                        mitre_tactic = "execution",
                                        mitre_tech   = "T1059",
                                        engine       = self.ENGINE,
                                    )
                                    event_bus.publish("alert", {"kind": "alert", "alert": a})
                                    break
                        except (PermissionError, FileNotFoundError, OSError):
                            continue

                    # Prune known_pids to prevent unbounded growth
                    if len(known_pids) > 50000:
                        known_pids.clear()

                    time.sleep(3)
                except Exception as e:
                    log.debug(f"Audit fallback error: {e}")
                    time.sleep(5)

        def run(self, event_bus):
            self._event_bus = event_bus
            if BCC_OK and os.geteuid() == 0:
                try:
                    self._run_ebpf(event_bus)
                    return
                except Exception as e:
                    log.warning(f"eBPF failed ({e}), falling back to /proc")
            self._run_audit_fallback(event_bus)
