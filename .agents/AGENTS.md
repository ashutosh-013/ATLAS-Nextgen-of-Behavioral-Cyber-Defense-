# ATLAS Development Guidelines (Final)

Rules and constraints for developers and AI agents working on the ATLAS Behavioral Cyber-Intelligence Platform.

## 1. Keep ATLAS Behavior-First
Signature detection is a supporting module, not the core. The main research contribution remains Behavioral DNA (d-BEF, BSF, NSF, CCF).

## 2. Never Let Any Module Bypass BADNA
Every telemetry event must always pass through the behavioral pipeline, even if an IOC or signature is matched.

## 3. Separate Responsibilities
* **IOC Repository**: Stores hashes, IPs, URLs, domains, CVEs.
* **Behavioral Knowledge Base**: Stores Behavioral DNA, campaigns, analyst feedback, threat intelligence, and historical behavior.
Do not mix them.

## 4. Use CCF for Confidence
Avoid hardcoded confidence boosts (e.g., +0.15). Let the Confidence Calibration Function (CCF) calculate the final confidence using all evidence.

## 5. Keep Quantum Optional
Implement Quantum Optimization as an independent optimization service with a classical fallback. Never make ATLAS depend on quantum hardware.

## 6. Optimize, Don't Overengineer
Every new module must have a clear purpose. Do not add features just because they sound advanced.

## 7. Build for Real Data
Prioritize:
* Correct data ingestion
* Parser quality
* Knowledge Base population
* End-to-end validation
over adding new AI models.

## 8. Keep Everything Modular
Each component should be replaceable without affecting the rest of the system.

## 9. Measure Everything
Every module should expose metrics:
* Processing time
* Detection latency
* Memory usage
* Detection confidence
* False positives
* False negatives

## 10. Research Before Marketing
Never claim "state-of-the-art" or "better than commercial EDR." Let the experimental results demonstrate the system's strengths.

---

## Core Focus Goal
Focus on making ATLAS a reliable Behavioral Cyber-Intelligence Platform, not a collection of AI features. Every module should contribute to understanding attacker behavior, improving the Behavioral Knowledge Base, or supporting better defensive decisions. If a feature does not improve detection, reasoning, or response, do not add it. Simplicity, correctness, and measurable performance are more valuable than additional complexity.
