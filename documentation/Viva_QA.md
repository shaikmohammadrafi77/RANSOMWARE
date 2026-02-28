Viva Questions and Answers – AI-Driven Framework for Ransomware Detection and Prevention
========================================================================================

1. What is ransomware?
----------------------
- **Answer**: Ransomware is a type of malicious software that encrypts a victim’s data and demands a ransom payment in exchange for the decryption key. It often spreads through phishing emails, exploit kits, or vulnerable services and can cause severe financial and operational damage.

2. Why are traditional antivirus solutions insufficient against ransomware?
---------------------------------------------------------------------------
- **Answer**: Traditional antivirus tools rely heavily on known malware signatures and static rules. Modern ransomware frequently uses polymorphism, encryption, and obfuscation techniques to change its appearance, making its signature unknown. As a result, purely signature-based systems fail to detect new variants and zero-day attacks.

3. What is the main goal of your project?
-----------------------------------------
- **Answer**: The goal is to build an **AI-driven, behavior-based framework** that monitors system activity in real time, extracts meaningful features, and uses machine learning models to classify behavior as normal or ransomware-like, and then automatically trigger prevention and response actions.

4. What types of features did you use to detect ransomware?
-----------------------------------------------------------
- **Answer**: We used behavioral features such as:
  - File modification rate.
  - Entropy-like variability of file sizes.
  - Number of files touched.
  - CPU and memory usage.
  - Approximate API calls (based on I/O counters).
  - Network bytes sent and received.
  - Suspicious file extension ratio.
  - Registry-like modification count (simulated).
  - Failed file access attempts.

5. Which machine learning algorithms did you use and why?
---------------------------------------------------------
- **Answer**: We used:
  - **Random Forest**: Robust to noise, handles non-linear relationships, easy to interpret feature importance.
  - **SVM with RBF kernel**: Effective at separating classes with complex boundaries.
  - **MLP Neural Network**: Captures non-linear interactions between features using learned hidden layers.
  We compare their performance and select the best based on F1 score.

6. What evaluation metrics did you use?
--------------------------------------
- **Answer**: We used **Accuracy**, **Precision**, **Recall**, **F1 Score**, and the **Confusion Matrix**. Precision and Recall are critical because we want to minimize false positives (normal behavior flagged as ransomware) and false negatives (missed ransomware).

7. Why is F1 score important in this context?
--------------------------------------------
- **Answer**: F1 score is the harmonic mean of Precision and Recall. In ransomware detection, both false positives and false negatives are costly, so focusing solely on accuracy can be misleading. F1 balances Precision and Recall, making it a better metric for imbalanced or high-risk classification tasks.

8. How does your monitoring agent work?
--------------------------------------
- **Answer**: The agent runs on the host machine and:
  - Uses `watchdog` to monitor file system events.
  - Uses `psutil` to measure CPU, memory, process I/O, and network usage.
  - Aggregates this telemetry into a feature snapshot at fixed intervals.
  - Sends the snapshot as JSON to the Flask backend via an HTTP POST request.

9. How does the backend detect ransomware?
------------------------------------------
- **Answer**: The Flask backend:
  - Loads the pre-trained ML pipeline.
  - Receives feature snapshots at `/api/ingest_features`.
  - Preprocesses the features and feeds them to the model.
  - Obtains a probability score for ransomware-like behavior.
  - Compares the score with a threshold; if above, it labels the behavior as ransomware and triggers response actions.

10. What prevention and response actions are implemented?
---------------------------------------------------------
- **Answer**: In this educational implementation, actions are **simulated** for safety. When ransomware-like behavior is detected, the system logs an incident and simulates actions such as:
  - Isolating suspicious processes.
  - Blocking further file writes.
  - Restricting network access.
  In a real deployment, these actions would be integrated with OS-level APIs and security tools.

11. How is data stored and visualized?
--------------------------------------
- **Answer**: Detected incidents and system health metrics are stored in an **SQLite** database. A **web dashboard** built with HTML, CSS, and JavaScript fetches this data via REST APIs (`/api/incidents`, `/api/system_health`) and displays:
  - Recent incidents table.
  - System CPU/memory usage.
  - Model performance metrics.

12. How do you ensure the system is safe to run on a normal machine?
--------------------------------------------------------------------
- **Answer**: The project:
  - Does **not** include any real malware or ransomware code.
  - Uses **synthetic data** for training to mimic ransomware-like behavior.
  - Simulates prevention actions without actually killing processes or modifying system settings.
  - Encourages running real malware only in isolated sandboxes or virtual machines, if ever required for research.

13. What are the main challenges you faced?
-------------------------------------------
- **Answer**: Key challenges include:
  - Obtaining realistic ransomware datasets safely.
  - Designing features that are discriminative yet inexpensive to compute.
  - Balancing detection sensitivity with false positive rates.
  - Ensuring low-latency inference suitable for real-time monitoring.

14. What are the limitations of your system?
-------------------------------------------
- **Answer**: Limitations include:
  - Synthetic datasets may not cover all real-world attack patterns.
  - Monitoring is at the user-space level and may miss kernel-level behaviors.
  - Some advanced evasion techniques (fileless, in-memory ransomware) are not explicitly modeled.
  - Currently focused on a single host rather than large-scale enterprise deployment.

15. How can this project be extended in the future?
---------------------------------------------------
- **Answer**: Possible extensions:
  - Integrate deeper OS hooks and EDR (Endpoint Detection & Response) tooling.
  - Apply deep learning (LSTM/transformers) to model temporal sequences of events.
  - Implement federated learning across multiple endpoints.
  - Support centralized cloud monitoring and analytics.
  - Develop adaptive thresholds that learn each user’s baseline.

16. Why did you choose Flask for the backend?
---------------------------------------------
- **Answer**: Flask is lightweight, easy to set up, and integrates naturally with Python-based ML stacks. It allows rapid development of REST APIs and is sufficient for a single-node backend used in this project.

17. Why did you choose SQLite as the database?
----------------------------------------------
- **Answer**: SQLite is file-based, requires no separate server, and is very simple to set up, making it ideal for a student project and single-host deployment. It can later be replaced with more scalable databases (e.g., PostgreSQL, MongoDB) if needed.

18. How does your system support continuous learning?
-----------------------------------------------------
- **Answer**: The framework:
  - Logs incidents and system behavior.
  - Allows exporting these logs as labeled data.
  - Provides a training script (`ml_model/train_model.py`) to retrain and update the model.
  - After retraining, the backend can reload the new model, improving detection over time.

19. How would you deploy this project in production?
----------------------------------------------------
- **Answer**: A typical approach:
  - Containerize the backend using Docker.
  - Deploy it on a cloud platform (AWS, Azure) or on-premise server.
  - Run agents on endpoints pointing to the central backend.
  - Use a more robust database and authentication for APIs.
  - Integrate with enterprise SIEM/SOC workflows.

20. What is the novelty of your project?
----------------------------------------
- **Answer**: The novelty lies in:
  - An end-to-end, modular framework combining monitoring, ML detection, prevention logic, and visualization.
  - A focus on behavior-based ransomware detection rather than static signatures.
  - A design that is practical, extensible, and suitable as a foundation for further research and industrial integration.

