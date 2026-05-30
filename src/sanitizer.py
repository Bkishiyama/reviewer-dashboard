# required for Python versions < 3.10
# makes all type annotations in this file behave like strings
from __future__ import annotations

#!/usr/bin/env python3

"""
src/sanitizer.py
Purpose: check client's updates for model poisoning attacks.
If detected, drop the offending client from the aggregation.
If not detected, aggregate the client's updates into the global model.
"""

import math
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

# for Logging
logger = logging.getLogger(__name__)

# Constants
DEFAULT_Z_THRESHOLD: float = 2.0  # Standard threshold to catch gross outliers or attack Z ≫ 2
LARGE_GROUP_Z_THRESHOLD: float = 2.0  # looser threshold for larger FL groups
LARGE_GROUP_SIZE: int = 10  # groups above this will use LARGE_GROUP_Z_THRESHOLD
MIN_HOSTS_FOR_STATS: int = 3  # Minimum hosts needed for Z-score calculation


# Data classes
# for each client, store the host_id, value, z_score, and whether it was accepted or rejected
@dataclass
class HostReport:
    host_id: str  # store the identifier who sent the update
    value: float  #  the value being sent and checked
    z_score: float  # the calculated Z-score for the client
    accepted: bool  # accepted clients data is true; rejected clients data is false
    reason: str = "" # store the reason for the decision

# store the results or number of accepted, rejected, and total hosts
@dataclass
class SanitizationReport:
    n_submitted: int  # total number of hosts submitted to the central server
    n_accepted: int  # number of hosts that passed the sanitization check
    n_rejected: int  # number of hosts that failed the sanitization check
    rejected_hosts: List[str]  # list containing the host_ids of the rejected hosts
    accepted_hosts: List[str]  # list containing the host_ids of the accepted hosts
    mean_before: float  # The average value of all submitted hosts before filtering
    std_dev: float  # standard deviation of all submitted values.
    global_model: float  # final aggregated global model value that determines if a client is trusted or not
    z_threshold: float  # the Z-score threshold used to determine if a client is rejected or not
    host_reports: List[HostReport] = field(default_factory=list) # list of detailed reports for each host

    # determine if suspicious hosts were detected; return true if any host was rejected
    @property
    def poisoning_detected(self) -> bool:
        return self.n_rejected > 0

    # display the summary of the sanitization report
    def summary_lines(self) -> List[str]:
        lines = [
            f"+-+-+ SANITIZATION REPORT +-+-+",
            f"- Submitted : {self.n_submitted} hosts",
            f"- Accepted  : {self.n_accepted} hosts → {self.accepted_hosts}",
            f"- Rejected  : {self.n_rejected} hosts → {self.rejected_hosts}",
            f"- Group mean (pre-filter) : {self.mean_before:.4f}",
            f"- Group std  (pre-filter) : {self.std_dev:.4f}",
            f"- Z-threshold used        : {self.z_threshold}",
            f"- Clean global model      : {self.global_model:.4f}",
        ]
        if self.poisoning_detected:
            lines.append(
                f"\033[91m  [!] POISONING DETECTED -> {self.n_rejected} host(s) dropped before aggregation\033[0m"
            )
        else:
            lines.append("-> No poisoning detected. All hosts contributed to aggregation")
        return lines


''' Scalar Sanitizer
Add and aggregate client updates to the FL model but eliminate abnormalities by using Z-score outlier filtering
Parameter: key (str) is the host_id
Parameter: value (float) is the scalar value of the host's update
This is the central server's entry point where each client uploads a single scalar value.
The function computes the mean and standard deviation of all submitted values,
then applies a Z-score threshold (cutoff if above) to determine if a client's update is an outlier or not.
If the client's update is an outlier, it is rejected and not included in the aggregated model.
Otherwise, the client's update is accepted and included in the aggregated model.
Return: global model, or the federated average of accepted hosts
Return: Each hosts details  
'''
def aggregate_with_sanitizer(
        client_updates: Dict[str, float],
        z_threshold: Optional[float] = None,
) -> Tuple[float, SanitizationReport]:

    if client_updates is None:
        raise ValueError("client_updates must not be None")

    hosts = list(client_updates.keys())
    values = list(client_updates.values())
    n = len(values)

    # Auto select Z-threshold based on small or large group size
    if z_threshold is None:
        z_threshold = LARGE_GROUP_Z_THRESHOLD if n >= LARGE_GROUP_SIZE else DEFAULT_Z_THRESHOLD

    print("\n=== RUNNING SECURITY SANITIZATION ===")

    # Case 1: if no host updates received, return the mean of all submitted values
    if n == 0:
        logger.warning("[SANITIZER] No updates received.")
        print("[SANITIZER] No updates received.")
        report = SanitizationReport(
            n_submitted=0, n_accepted=0, n_rejected=0,
            rejected_hosts=[], accepted_hosts=[],
            mean_before=0.0, std_dev=0.0, global_model=0.0,
            z_threshold=z_threshold,
        )
        return 0.0, report

    # Case 2: if few hosts sent updates for a meaningful Z-score
    if n < MIN_HOSTS_FOR_STATS:
        msg = (
            f"[SANITIZER] Only {n} host(s) — too few for statistical screening. "
            "Proceeding with standard average (no filtering applied)."
        )
        logger.warning(msg)
        print(msg)
        avg = sum(values) / n
        report = SanitizationReport(
            n_submitted=n, n_accepted=n, n_rejected=0,
            rejected_hosts=[], accepted_hosts=hosts,
            mean_before=avg, std_dev=0.0, global_model=avg,
            z_threshold=z_threshold,
            host_reports=[
                HostReport(h, v, 0.0, True, "too few hosts for Z-score screening")
                for h, v in client_updates.items()
            ],
        )
        return avg, report

    # Compute the group mean and standard deviation
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std_dev = math.sqrt(variance)

    # Case 3: if all hosts have the same value, return the mean
    if std_dev == 0:
        msg = "[!SANITIZER] All host weights match perfectly -> No anomalies."
        logger.info(msg)
        print(msg)
        report = SanitizationReport(
            n_submitted=n, n_accepted=n, n_rejected=0,
            rejected_hosts=[], accepted_hosts=hosts,
            mean_before=mean, std_dev=0.0, global_model=mean,
            z_threshold=z_threshold,
            host_reports=[
                HostReport(h, v, 0.0, True, "perfect consensus") for h, v in client_updates.items()
            ],
        )
        return mean, report

    ''' Z-score filtering loop
    Analyze each host's update against the group mean and standard deviation.
    If the Z-score is above the threshold, the host is rejected and not included in the aggregated model.
    Otherwise, the host is accepted and included in the FL aggregated model.
    '''
    # To store the accepted hosts, clean values, and rejected hosts
    host_reports: List[HostReport] = []
    clean_values: List[float] = []
    clean_hosts: List[str] = []
    rejected_hosts: List[str] = []

    # check every client submission
    for host, val in client_updates.items():
        z = abs(val - mean) / std_dev  # compute Z-score
        accepted = z <= z_threshold  # decide if accepted

        # if update is accepted else rejected
        if accepted:
            clean_values.append(val)
            clean_hosts.append(host)
            reason = "within acceptable range"
        else:
            rejected_hosts.append(host)
            reason = f"Z-score {z:.2f} exceeds threshold {z_threshold}"
            print(
                f"\033[91m[! SECURITY ALERT]\033[0m Host {host} REJECTED — "
                f"Potential Model Poisoning Detected! "
                f"(value={val:.4f}, Z={z:.2f})"
            )
            logger.warning(
                "POISONING DETECTED: host=%s value=%.4f z_score=%.2f threshold=%.1f",
                host, val, z, z_threshold,
            )

        hr = HostReport(host_id=host, value=val, z_score=z, accepted=accepted, reason=reason)
        host_reports.append(hr)
        print(
            f"-> Host {host:4s}: value={val:<8.4f} Z={z:.2f}  "
            f"{'[+] ACCEPTED' if accepted else '[-] REJECTED'}"
        )

    # compute the final global model
    if not clean_values:  # check if empty
        msg = (
            "[! SANITIZER] CRITICAL: All hosts rejected! "
            "Falling back to unfiltered mean to avoid model collapse."
        )
        logger.error(msg)
        print(msg)
        global_model = mean          # Fallback to pre-filter mean; do not crash
        clean_hosts = hosts          # just report all as "accepted" when fallback used
    else:
        global_model = sum(clean_values) / len(clean_values) # some valid clients found
    # display final computed model value with # of clients
    print(f"\n  Clean global model: {global_model:.4f}  "
          f"({len(clean_values)}/{n} hosts contributed)\n")

    # sanitation report
    report = SanitizationReport(
        n_submitted=n,
        n_accepted=len(clean_hosts),
        n_rejected=len(rejected_hosts),
        rejected_hosts=rejected_hosts,
        accepted_hosts=clean_hosts,
        mean_before=mean,
        std_dev=std_dev,
        global_model=global_model,
        z_threshold=z_threshold,
        host_reports=host_reports,
    )
    return global_model, report


'''
A function that is a extended version of the Z-score filtering loop. Each clients sends
a list of numbers as a vector or parameter array, and not a single number. This will
remove malicious clients before building a global model. Basically, this deals with
clients that upload all of the Isolation Forest parameters and not a single metric.
Returns average parameter vector and sanitation report.
'''
def sanitize_vector_updates(
        client_updates: Dict[str, List[float]],
        z_threshold: Optional[float] = None,
        reduce: str = "mean",  # convert vector to a single number
) -> Tuple[List[float], SanitizationReport]:

    # Reduce each host's vector to a representative scalar
    scalar_updates: Dict[str, float] = {}  # empty dictionary
    for host, vec in client_updates.items():  # loop through each client vector
        if not vec:  # if empty vector
            scalar_updates[host] = 0.0
            continue
        if reduce == "mean":  # mean reduction
            scalar_updates[host] = sum(vec) / len(vec)  # average all values
        elif reduce == "max":  # max reduction
            scalar_updates[host] = max(vec)
        elif reduce == "norm":  # L2 norm
            scalar_updates[host] = math.sqrt(sum(x ** 2 for x in vec))
        elif reduce == "first":  # first element
            scalar_updates[host] = vec[0]
        else:
            raise ValueError(f"Unknown reduce method: {reduce!r}")

    # pass the reduced values into the sanitizer, run Z-score filtering, detect poisoned clients
    _, report = aggregate_with_sanitizer(scalar_updates, z_threshold=z_threshold)

    # Compute final cleaned global vector using the accepted host set
    accepted = set(report.accepted_hosts)
    clean_vecs = [vec for h, vec in client_updates.items() if h in accepted] # only clean vectors

    if not clean_vecs:
        # Fallback on average if everything is rejected
        clean_vecs = list(client_updates.values())

    vec_len = max(len(v) for v in clean_vecs)  # find max vector
    global_vec: List[float] = []  # Build the global vector
    for i in range(vec_len):
        col = [v[i] for v in clean_vecs if i < len(v)]
        global_vec.append(sum(col) / len(col) if col else 0.0)

    # Finish building and create a summary score for display
    report.global_model = math.sqrt(sum(x ** 2 for x in global_vec))
    return global_vec, report
