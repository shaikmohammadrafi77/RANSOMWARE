# 🎓 Project Viva Questions & Answers
**Project**: Cortex - AI-Driven Ransomware Defense System

Use this document to answer questions during your project presentation or viva.

---

## 🧠 Machine Learning & Dataset Questions

### Q1: Which Machine Learning algorithm/model did you use?
**Answer**: I used a **Deep Learning Neural Network (Multi-Layer Perceptron)**.
- It is a "Feed-Forward" Artificial Neural Network.
- It has **3 Fully Connected Layers** (Dense Layers):
  1. Input Layer (12 features)
  2. Hidden Layers (32 and 16 neurons with ReLU activation)
  3. Output Layer (1 neuron with Sigmoid activation to output a probability score).

### Q2: Where did you get the dataset? (Which dataset is this?)
**Answer**: This is a **Synthetic Behavioral Dataset** generated specifically for this project.
- **Why?**: Public datasets for ransomware *behavior* (runtime metrics like CPU, RAM, file I/O) are extremely scarce and often outdated.
- **How it works**: I wrote a script (`ml_model/train_model.js`) that simulates data points:
  - **Normal Class**: Simulates a user browsing the web (Low file I/O, variable CPU).
  - **Ransomware Class**: Simulates an encryption attack (High file write speed, High Entropy, High CPU usage).

### Q3: What features are you using to detect ransomware?
**Answer**: The model monitors **12 Key Behavioral Indicators**:
1. `file_modification_rate`: How many files are being changed per second.
2. `entropy_rate`: High entropy indicates encrypted (random-looking) data.
3. `suspicious_extension_ratio`: Files renamed to weird extensions (e.g., `.locked`, `.crypt`).
4. `cpu_usage`: Encryption is math-heavy and consumes CPU.
5. `memory_usage`: RAM consumption.
6. `network_bytes_sent`: Potential data exfiltration (stealing data).
7. *...and others like `num_files_touched`, `registry_modifications`, etc.*

### Q4: What is the accuracy of your model?
**Answer**: On the synthetic validation set, the model achieves **>95% accuracy**. This is expected because the synthetic patterns are distinct. In a real-world scenario, I would retrain it on real malware traces (e.g., from CIC-MalMem-2022 dataset) for production use.

---

## 💻 Technical & Implementation Questions

### Q5: How does the "Real-Time" detection work?
**Answer**:
1. The **Frontend/Client** queries the system metrics every few seconds.
2. The **Backend** captures a "snapshot" of the current system state (CPU, RAM, simulated file ops).
3. This snapshot is sent to the **ML Model**.
4. The Model calculates a **Risk Score** (0.0 to 1.0).
5. If Score > 0.7, it flags an **Incident** and triggers the response module.

### Q6: What does the system do when it finds Ransomware?
**Answer**: It triggers a **Prevention Action**:
- In this demo, it simulates **Isolating the Process** (killing the suspicious program) and **Blocking Network Access**.
- It logs the incident to the **SQLite Database** for forensic review.
- It updates the Dashboard immediately to warn the user.

### Q7: Why did you choose Web Technologies (Node/Flask/HTML)?
**Answer**:
- **Portability**: Web dashboards can be accessed remotely by security admins.
- **Visualization**: HTML/CSS allows for rich, real-time graphs that are harder to build in desktop GUIs.
- **Scalability**: The backend API can easily be extended to monitor multiple computers, not just one.

---

## 🛡️ Future Enhancements

### Q8: How would you improve this project in the future?
**Answer**:
1. **Real Data**: Train on the *CIC-AndMal2017* or *CIC-MalMem-2022* datasets.
2. **File Recovery**: Implement a "Shadow Copy" features to automatically restore files if they get encrypted.
3. **Agent Deployment**: Create a standalone `.exe` agent that runs silently on victim machines and reports back to this server.
