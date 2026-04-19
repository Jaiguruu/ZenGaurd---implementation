# ZenGuard Zero Trust Pipeline: Architecture

## High-Level Abstraction (C4 Context)

```mermaid
graph TD
    classDef siem fill:#3b82f6,stroke:#1e3a8a,stroke-width:2px,color:#fff;
    classDef ueba fill:#ec4899,stroke:#831843,stroke-width:2px,color:#fff;
    classDef soar fill:#10b981,stroke:#064e3b,stroke-width:2px,color:#fff;

    Net[Network Traffic/Datasets] --> SIEM(SIEM: Logstash & Elasticsearch):::siem
    User[End User/Attacker] --> Net
    
    SIEM -->|Polled Event JSON| UEBA(UEBA: FastAPI & ML):::ueba
    UEBA -->|Risk Score & Context| SOAR(SOAR: RL Agent & Playbooks):::soar
    
    SOAR -->|Mitigation Actions| Firewalls[Firewalls,IAM,Endpoints]
```

## System Components

```mermaid
graph LR
    subgraph SIEM[The Cameras: SIEM Module]
        R[Replayer Script] --> L[Logstash Pipeline]
        L --> E[(Elasticsearch / SQLite)]
        E --> S[SIEM Listener]
    end

    subgraph UEBA[The Profiler: UEBA Module]
        S -- "POST /api/ueba/predict" --> API[FastAPI Server]
        Train[generate_dataset.py] -.->|Offline Train| Model[(model.joblib)]
        API <--> Model
    end

    subgraph SOAR[The Guards: SOAR Module]
        API -- "JSON Risk Context" --> Engine[SOAR Engine]
        Engine <--> RL[Q-Learning Table]
        Engine --> PB[Deterministic Playbooks]
    end
```

## Modular Deployment vs Integrated
**Modular Usage:**
Each subsystem is heavily decoupled. 
- You can run the **UEBA offline** completely isolated by just dumping the feature engineered CSVs and running `test_unit.py`. 
- You can run the **SIEM alone** by piping CSVs through ELK without ever forwarding events out of Elasticsearch.

**Integrated Usage:**
When connected natively, `Implemetations/SIEM/siem_listener.py` bridges the gap, intercepting buffers in Elasticsearch and shooting POST requests strictly to the endpoints established in `Implemetations/UEBA_V2/model_server.py`, which translates the inputs for the final mitigation stage located remotely in the SOAR layer.
