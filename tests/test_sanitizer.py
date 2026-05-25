""" tests/test_sanitizer.py
This is for Tool 2 Unit Tests: Model Poisoning Sanitizer
Testing cover:
1. Healthy network behavior - no poisoning should be detected in clean data
2. Single poisoned host - detection and rejection of a malicious node, host 6
3. Multiple poisoned hosts - works when more than one adversarial host
4. Edge cases: empty input, single host, two hosts, and values are all the same
5. Vector sanitizer - handles a host when it sends a vector instead of a single number
6. Z-threshold sensitivity - to determine if valid as strictness is adjusted

Run with -> python3 -m pytest tests/test_sanitizer.py -v
"""

from __future__ import annotations

import math
import pytest
from src.sanitizer import (
    aggregate_with_sanitizer,
    sanitize_vector_updates,
    SanitizationReport,
    DEFAULT_Z_THRESHOLD,
    MIN_HOSTS_FOR_STATS,
)

# Fixtures - ready to use resources
HEALTHY_DATA = {
    "h1": 0.12,
    "h2": 0.15,
    "h3": 0.11,
    "h4": 0.13,
    "h5": 0.14,
    "h6": 0.12,
}

POISONED_DATA = {
    "h1": 0.12,
    "h2": 0.15,
    "h3": 0.11,
    "h4": 0.13,
    "h5": 0.14,
    "h6": 4.50,   # Notice the gross outlier that simulates a poisoning attack
}


# Healthy network
class TestHealthyNetwork:
    # a single test case that is healthy
    def test_no_hosts_rejected(self):
        _, report = aggregate_with_sanitizer(HEALTHY_DATA)
        assert report.n_rejected == 0 # healthy dataset should not reject the host

    # ensure benign clients are not droppped
    def test_all_hosts_accepted(self):
        _, report = aggregate_with_sanitizer(HEALTHY_DATA)
        assert report.n_accepted == len(HEALTHY_DATA)

    # no poisoning detected - no false positives
    def test_poisoning_not_flagged(self):
        _, report = aggregate_with_sanitizer(HEALTHY_DATA)
        assert not report.poisoning_detected

    # ensure aggregation uses standard mean for clean conditions
    def test_global_model_is_mean(self):
        global_model, report = aggregate_with_sanitizer(HEALTHY_DATA)
        expected = sum(HEALTHY_DATA.values()) / len(HEALTHY_DATA)
        assert math.isclose(global_model, expected, rel_tol=1e-5)

    # ensures API functions remain stable or predictably
    def test_report_type(self):
        global_model, report = aggregate_with_sanitizer(HEALTHY_DATA)
        assert isinstance(global_model, float)
        assert isinstance(report, SanitizationReport)


# Single poisoned host
class TestSinglePoisonedHost:
    # Tests that a known malicious host (h6) is correctly identified and rejected
    def test_h6_is_rejected(self):
        _, report = aggregate_with_sanitizer(POISONED_DATA)
        assert "h6" in report.rejected_hosts

    # Tests that the sanitizer correctly detects the presence of poisoning in the dataset
    def test_poisoning_detected(self):
        _, report = aggregate_with_sanitizer(POISONED_DATA)
        assert report.poisoning_detected

    # Ensures that only one malicious host is rejected in this poisoned scenario
    def test_n_rejected_is_one(self):
        _, report = aggregate_with_sanitizer(POISONED_DATA)
        assert report.n_rejected == 1

    # Verifies that all non-malicious hosts, h1–h5, are accepted by the sanitizer
    def test_clean_hosts_are_h1_to_h5(self):
        _, report = aggregate_with_sanitizer(POISONED_DATA)
        assert set(report.accepted_hosts) == {"h1", "h2", "h3", "h4", "h5"}

    # Checks that the global model is computed using only clean hosts,
    # ensuring the malicious host (h6) does not influence the final aggregation
    def test_global_model_excludes_h6(self):
        global_model, report = aggregate_with_sanitizer(POISONED_DATA)

        # Compute expected mean using only non-rejected (clean) hosts
        clean_vals = [v for h, v in POISONED_DATA.items() if h != "h6"]
        expected = sum(clean_vals) / len(clean_vals)

        # Validate that sanitized aggregation matches expected clean-only mean
        assert math.isclose(global_model, expected, rel_tol=1e-4)


    # Global model, after sanitized from an attack, should look like a clean,
    # healthy model and not the one from FedAvg.
    def test_sanitizer_improves_accuracy(self):
        # remove poisoned data and make a sanitized global model
        global_sanitized, _ = aggregate_with_sanitizer(POISONED_DATA)
        # make a model without sanitation
        global_naive = sum(POISONED_DATA.values()) / len(POISONED_DATA)
        # make a model with no attacks
        healthy_mean = sum(HEALTHY_DATA.values()) / len(HEALTHY_DATA)

        # Measures whether the sanitizer improved under poisoning.
        # We compare how close the sanitized model is to the true (healthy) mean
        # against a naive FedAvg model that includes poisoned updates.
        dist_sanitized = abs(global_sanitized - healthy_mean)
        dist_naive = abs(global_naive - healthy_mean)

        # The sanitizer should reduce the effect of poisoning,
        # meaning its output should be closer to the healthy baseline
        assert dist_sanitized < dist_naive, (
            f"Sanitizer ({global_sanitized:.4f}) should be closer to healthy mean "
            f"({healthy_mean:.4f}) than naive FedAvg ({global_naive:.4f})"
        )


# Edge cases
class TestEdgeCases:
    # This tests when no client updates are provided.
    # The sanitizer should handle empty input without errors,
    # and return a neutral global model and an empty report.
    def test_empty_input(self):
        global_model, report = aggregate_with_sanitizer({})
        # With no data, the aggregated model should default to 0.0
        assert global_model == 0.0
        # No clients were submitted, so the report should reflect zero inputs
        assert report.n_submitted == 0

    # Single host - too few for Z-score; should be accepted without filtering
    def test_single_host(self):
        global_model, report = aggregate_with_sanitizer({"h1": 0.12})
        assert report.n_accepted == 1
        assert report.n_rejected == 0

    # Two hosts - still below MIN_HOSTS_FOR_STATS; no filtering applied
    def test_two_hosts(self):
        global_model, report = aggregate_with_sanitizer({"h1": 0.12, "h2": 5.00})
        assert report.n_rejected == 0    # Filtering disabled for tiny groups

    # All values are identical → std_dev = 0.
    # With no variation, the sanitizer has nothing to filter out, so every update is accepted.
    def test_all_same_values(self):
        data = {f"h{i}": 0.13 for i in range(1, 7)}
        global_model, report = aggregate_with_sanitizer(data)
        assert report.n_rejected == 0
        assert math.isclose(global_model, 0.13)

    # When every host sends an extreme (poisoned) value, the sanitizer rejects them all.
    # With no valid updates left, it falls back to using the mean of the original inputs.
    def test_all_hosts_poisoned_fallback(self):
        data = {"h1": 100.0, "h2": 200.0, "h3": 300.0, "h4": 400.0}
        global_model, report = aggregate_with_sanitizer(data)
        # All updates should be rejected, and the fallback mean should still be a valid number.
        assert global_model > 0.0  # Ensures the fallback worked and did not return 0 or crash

    # Passing None is invalid input. The sanitizer should detect this and raise a ValueError.
    def test_none_input_raises(self):
        with pytest.raises(ValueError):
            aggregate_with_sanitizer(None)

    # A very strict z-threshold (0.5) should flag more hosts as outliers.
    # A loose threshold (3.0) should reject fewer hosts.
    def test_custom_z_threshold_strict(self):
        data = {"h1": 0.10, "h2": 0.13, "h3": 0.11, "h4": 0.20, "h5": 0.12, "h6": 0.11}
        _, report_strict = aggregate_with_sanitizer(data, z_threshold=0.5)
        _, report_loose = aggregate_with_sanitizer(data, z_threshold=3.0)
        # The strict setting must reject at least as many hosts as the loose one.
        assert report_strict.n_rejected >= report_loose.n_rejected


# Vector sanitizer
class TestVectorSanitizer:
    # All hosts provide similar, low‑variance vectors.
    # Since none of the updates look like outliers, the sanitizer should accept all of them.
    def test_healthy_vectors_all_accepted(self):
        data = {
            "h1": [0.1, 0.2, 0.3],
            "h2": [0.11, 0.19, 0.31],
            "h3": [0.12, 0.21, 0.29],
            "h4": [0.10, 0.20, 0.30],
            "h5": [0.13, 0.22, 0.28],
        }
        _, report = sanitize_vector_updates(data)
        # No vectors should be rejected because all updates are healthy and consistent.
        assert report.n_rejected == 0

    # Most hosts provide normal, low‑variance vectors.
    # One host ("h6") sends an extremely large vector that is clearly poisoned.
    # The sanitizer should detect this outlier and reject it.
    def test_poisoned_vector_rejected(self):
        data = {
            "h1": [0.1, 0.2, 0.3],
            "h2": [0.11, 0.19, 0.31],
            "h3": [0.12, 0.21, 0.29],
            "h4": [0.10, 0.20, 0.30],
            "h5": [0.13, 0.22, 0.28],
            "h6": [10.0, 20.0, 30.0],   # Grossly inflated -> should be rejected
        }
        _, report = sanitize_vector_updates(data)
        assert "h6" in report.rejected_hosts

    # Create synthetic client updates:
    # Each host h1..h5 contributes a 2-dimensional vector [x, y]
    def test_output_vector_length(self):
        data = {f"h{i}": [0.1 * i, 0.2 * i] for i in range(1, 6)}

        # Run the sanitizer + aggregation function
        # vec is the resulting aggregated (global) vector
        # _ is the report/metadata (ignored here)
        vec, _ = sanitize_vector_updates(data)

        # Ensure the output vector has the expected dimensionality
        # Since each input vector has 2 elements, the output should also be length 2
        # This ensures the sanitizer does not change vector shape during processing
        assert len(vec) == 2


# SanitizationReport
# Run the sanitizer on a clean (healthy) dataset
# We ignore the aggregated model and only inspect the report object
class TestSanitizationReport:
    def test_summary_lines_is_list(self):
        _, report = aggregate_with_sanitizer(HEALTHY_DATA)
        # Generate human-readable summary lines from the report
        lines = report.summary_lines()
        # Ensure the output is a list (not a string, dict, etc.)
        # This verifies the API format is consistent and machine-readable
        assert isinstance(lines, list)
        # A valid report should never be empty if processing occurred
        assert len(lines) > 0


    def test_poisoning_detected_property(self):
        # Run sanitizer on clean (healthy) data
        # This should represent normal, non-adversarial behavior
        _, report_healthy = aggregate_with_sanitizer(HEALTHY_DATA)
        # Run sanitizer on poisoned/adversarial data
        # This simulates a real attack scenario where some clients are malicious
        _, report_poisoned = aggregate_with_sanitizer(POISONED_DATA)
        # On healthy data, the sanitizer should not detect poisoning
        assert not report_healthy.poisoning_detected
        # On poisoned data, the sanitizer should detect malicious behavior
        assert report_poisoned.poisoning_detected

    def test_host_reports_count(self):
        # Run the sanitizer on a healthy dataset of client updates
        # The function returns both the aggregated model and a detailed report
        _, report = aggregate_with_sanitizer(HEALTHY_DATA)

        # Ensure we got one report entry per input host
        # This checks that no hosts are dropped silently from reporting
        # and that every client update is accounted for in the sanitizer output
        assert len(report.host_reports) == len(HEALTHY_DATA)
