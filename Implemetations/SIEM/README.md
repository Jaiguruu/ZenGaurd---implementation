# SIEM Module: Developer Guide

**Role Analogy:** *The Security Cameras*  
Your job is strictly ingestion and observation. You don't make decisions about anomaly detection, and you certainly do not execute mitigation playbooks. You monitor the network, format the data, and alert the central authority.

## Your Responsibilities
- Manage the Logstash pipeline and Elasticsearch mappings to capture massive datasets flawlessly. 
- You ingest 80+ column density network statistics (e.g. from the CIC-IDS 2017 files).
- You utilize `zenguard_replayer.py` to synthesize identity fields (fake `failed_logins` limits, dropping `MFA_bypassed`, etc).
- Host the `siem_listener.py` agent to act as a courier polling your dashboards and flushing actionable sets out to the rest of the pipeline.

## What You Need To Know About UEBA
- UEBA **cannot ingest standard network Layer 4 variables** (packet counts etc). They rely completely on you parsing those into the 7 behavioral synthetic features defined in `siem_listener.py`. 
- The UEBA expects data cleanly modeled in JSON. You must execute standard HTTP `POST` commands to their endpoint `/api/ueba/predict` or `/api/soar/evaluate` carrying the exact `UEBAPayload` BaseModel.

## What You Need To Know About SOAR
- **Absolutely Nothing.**
- The system is decoupled. You never instruct the SOAR what to block or what to shut down. You forward intelligence up to the UEBA, and your responsibility ends there.
