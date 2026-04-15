# ZenGuard UEBA & SIEM/SOAR Documentation

Below is the Wiki Architect Documentation for the ZenGuard implementation, describing how the User and Entity Behavior Analytics (UEBA), SIEM, and SOAR pipelines work synergistically.

```json
{
  "name": "ZenGuard",
  "title": "ZenGuard Framework Documentation",
  "prompt": "You are a new engineer onboarding to the ZenGuard zero-trust framework. This wiki provides a high-level conceptual mapping and a guided technical walkthrough.",
  "children": [
    {
      "name": "onboarding",
      "title": "Onboarding",
      "prompt": "Read the entire Onboarding guide for both high-level insights and a path towards development zero-to-hero proficiency.",
      "children": [
        {
          "name": "principal_guide",
          "title": "Principal-Level Guide",
          "prompt": "High-level architectural insight: ZenGuard replaces static SIEM correlation with adaptive UEBA using an Isolation Forest model to detect lateral movement and insider threats dynamically. The critical insight is assigning discrete risk scores (e.g., 95 vs 50) based on anomaly outputs from the Isolation Forest, which are then funneled directly to SOAR for real-time automated mitigations like MFA enforcement and endpoint isolation.",
          "children": []
        },
        {
          "name": "zero_to_hero",
          "title": "Zero to Hero Guide",
          "prompt": "Progressive path: 1) Understand traditional SIEM limits vs Zero-Trust Architecture. 2) Learn scikit-learn Isolation Forest (`ZenGuard_UEBA_Anomaly_Detection.ipynb:100`). 3) Study how the model maps anomalies to SOAR actions based on outputs. 4) Run the Colab notebook to generate the trained `zenguard_ueba_model.pkl` artifact.",
          "children": []
        }
      ]
    },
    {
      "name": "getting_started",
      "title": "Getting Started",
      "prompt": "A quick reference to the project structure and setup.",
      "children": [
        {
          "name": "overview",
          "title": "Overview",
          "prompt": "ZenGuard unifies SIEM, SOAR, and UEBA in a vendor-neutral, API-first architecture. It leverages scikit-learn for model training and Python for automated incident response playbooks.",
          "children": []
        },
        {
          "name": "setup",
          "title": "Setup",
          "prompt": "Install dependencies: `pip install kagglehub pandas numpy scikit-learn joblib`. Execute the Jupyter Notebook to download the CICIDS2017 dataset via the Kaggle API.",
          "children": []
        }
      ]
    },
    {
      "name": "deep_dive",
      "title": "Deep Dive",
      "prompt": "Dive deep into the ZenGuard system architecture and machine learning subsystem.",
      "children": [
        {
          "name": "architecture",
          "title": "Architecture",
          "prompt": "SIEM Aggregation -> Python Listener -> UEBA (Isolation Forest Model) -> SOAR Decision Engine Playbooks -> Automated Mitigations (MFA/Isolation).",
          "children": []
        },
        {
          "name": "ueba_model",
          "title": "UEBA Model details",
          "prompt": "Uses a computationally lightweight scikit-learn Pipeline with an `IsolationForest(n_estimators=100, contamination=0.05)` configured for rapid scoring.",
          "children": []
        }
      ]
    }
  ]
}
```

## Onboarding Guide

### Principal-Level Guide
ZenGuard transcends traditional threshold-based SIEM models by integrating continuous Machine Learning. Our core architectural insight is moving from "alert-centric" security to "adaptively enforced" Zero Trust Architecture (ZTA).
We use the **Isolation Forest** algorithmic model (capable of `O(n log n)` fast training times) to profile normalized telemetry in near real-time without needing high-power GPU clusters, ensuring deployability and scale. The system processes normalized attributes (like session_duration, privilege_changes, device_trust_score) to output interpretable risk classifications, bridging SIEM events with automated SOAR decisive playbooks.

**Key mechanism:**
When an event yields `anomaly_score < threshold`, the UEBA engine emits a discrete `risk_score = 95` (high risk) invoking strict orchestration such as MFA challenge prompts or complete endpoint device quarantine, effectively overriding static trust policies.

### Zero-to-Hero Learning Path

**Part I: Foundations**
- Familiarize yourself with Python data science tools (`scikit-learn` and `pandas` skills). 
- Learn about `IsolationForest` capabilities from `scikit-learn`, particularly `n_estimators` and `contamination` logic.
- Review ZTA fundamentals and Security Orchestration Automation & Response (SOAR) principles.

**Part II: The Architecture Mapping**
- Trace the ZenGuard threat flow: Internal and external endpoints and firewalls send raw telemetry logs to the SIEM stack. The SIEM correlates and parses the metadata (IPs, Events), forwarding them to our Python Listener.
- The Listener hands these inputs to the Machine Learning component (UEBA). The Isolation Forest assesses the behavioral baseline and returns a scaled risk matrix (e.g. 50 or 95).
- The SOAR playbooks accept the scores as triggers. Catching a *95* prompts immediate network block action via APIs (firewall level) or authentication locks (IdP level). 

**Part III: Dev & Execution**
- Launch the provided `ZenGuard_UEBA_Anomaly_Detection.ipynb` notebook in Colab or a local Jupyter environment.
- Step 1: It integrates `kagglehub` dynamically fetching the *CICIDS2017* sample to proxy complex interaction datasets as proof of concept.
- Step 2-4: Execute the cells to preprocess feature vectors continuously and train the pipeline.
- Step 5: The pipeline dumps an operational `zenguard_ueba_model.pkl` artifact. In a live SOC integration, ZenGuard's backend script loads this PKL to evaluate inbound streams perpetually!
