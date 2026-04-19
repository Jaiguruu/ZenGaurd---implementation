# Wiki Catalogue

```json
{
  "project_name": "ZenGuard Zero Trust Pipeline",
  "items": [
    {
      "title": "Onboarding",
      "name": "onboarding",
      "children": [
        {
          "title": "Principal-Level Guide",
          "name": "principal_guide",
          "prompt": "Read d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\README.md and d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\docs\\adr\\0001-ueba-soar-contract.md to document the core insights. The architecture strictly decouples standard log aggregation (SIEM) from mathematical heuristic identification (UEBA V2) and autonomous mitigation (SOAR). Trade-offs include the decoupling layer added in UEBA V2 mapping raw forest matrices to SOAR-understandable risk bands."
        },
        {
          "title": "Zero to Hero Guide",
          "name": "zero_to_hero",
          "prompt": "Map the data flow: Start at d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\Implemetations\\SIEM\\zenguard_replayer.py (how data enters the stack via TCP). Understand Elasticsearch mappings in the docker ELK stack. Trace the polling layer at Implemetations/SIEM/siem_listener.py into the machine learning module in Implemetations/UEBA_V2/model_server.py. Conclude with mitigation playbooks at Implemetations/SOAR/engine.py."
        }
      ]
    },
    {
      "title": "Deep Dive: Machine Learning Pipeline",
      "name": "machine_learning",
      "children": [
        {
          "title": "UEBA Model Server",
          "name": "ueba_model_server",
          "prompt": "Review d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\Implemetations\\UEBA_V2\\model_server.py to understand how the FastAPI interacts with the persistent model.joblib to translate non-deterministic float anomaly scores into SOAR integer bands."
        },
        {
          "title": "Offline Data Engineer",
          "name": "data_engineering",
          "prompt": "Review d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\Implemetations\\UEBA_V2\\generate_dataset.py and train.py. Note how standard CIC-IDS data bypasses network constraints to quickly offline train an Isolation Forest."
        }
      ]
    },
    {
      "title": "Deep Dive: SOAR Subsystem",
      "name": "soar_subsystem",
      "children": [
        {
          "title": "State Action Reinforcement Logic",
          "name": "rl_logic",
          "prompt": "Review d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\Implemetations\\SOAR\\rl_agent.py. Look at SOARRLAgent and interpret the Q-Learning tables that balance action-impact constraints mapped against the discrete risk inputs."
        },
        {
          "title": "Playbook Engine",
          "name": "playbook_engine",
          "prompt": "Review d:\\Pranav\\University\\SEM-6\\Mini Project\\pranav-branch\\ZenGaurd---implementation\\Implemetations\\SOAR\\engine.py to evaluate the deterministic fallbacks prioritizing mitigations based on Contexts passed down from the UEBA."
        }
      ]
    }
  ]
}
```
