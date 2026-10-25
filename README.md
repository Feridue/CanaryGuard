# CanaryGuard
### A Confidence-Based Ransomware Detection and Containment System

CanaryGuard is a cybersecurity assignment project focused on detecting suspicious file-system activity associated with potential ransomware attacks. It combines file and process monitoring, behavioral analysis, confidence scoring, evidence logging, and response mechanisms to support the identification and handling of potential threats.

## Project Overview

Ransomware can disrupt systems by modifying files and making data inaccessible. CanaryGuard explores a defensive approach to identifying potentially malicious behavior by monitoring activity and analyzing suspicious events.

The project is organized into modular components to support monitoring, detection, evidence collection, response, and testing.

## Key Components

- **Monitoring:** Observes file-system and process activity.
- **Canary Management:** Supports the management of canary files used in detection.
- **Behavioral Analysis:** Correlates suspicious events and evaluates their confidence scores.
- **Evidence Logging:** Records information relevant to detected activity.
- **Threat Response:** Provides mechanisms for responding to potential threats.
- **Simulation:** Supports controlled testing of ransomware-like behavior.
- **User Interface:** Provides interface components for interacting with the application.
- **Automated Testing:** Includes tests for validating project functionality.

## Project Architecture

```text
CanaryGuard/
├── analysis/
│   ├── confidence.py
│   └── correlator.py
├── canary/
│   └── manager.py
├── evidence/
│   └── logger.py
├── monitoring/
│   ├── filesystem.py
│   ├── file_monitor.py
│   └── process.py
├── response/
│   └── containment.py
├── simulator/
│   └── ransom_sim.py
├── tests/
├── ui/
├── config.json
├── main.py
├── requirements.txt
└── test_monitor.py
```

## Technologies

- **Python** — Application logic and core functionality
- **Git and GitHub** — Version control and collaborative development
- **Pytest** — Automated testing, if installed and configured for the project

## Getting Started

### Prerequisites

- Python 3 installed and available from the command line
- Git installed
- Windows, Linux, or another supported environment, subject to project compatibility

### 1. Clone the Repository

```bash
git clone https://github.com/Feridue/CanaryGuard.git
cd CanaryGuard
```

### 2. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Run the Application

The main entry point is `main.py`. From the project directory, run:

```bash
python main.py
```

Review the configuration and project instructions before running the application. The startup command and supported environment should be verified against the current implementation.

### 4. Run the Tests

If pytest is not included in the installed dependencies, install it with:

```bash
python -m pip install pytest
```

Run the test suite:

```bash
python -m pytest
```

Review the test results to identify any failures or environment-specific requirements.

## Project Structure

| Directory or file | Purpose |
|---|---|
| `analysis/` | Confidence scoring and event correlation |
| `canary/` | Canary file management |
| `evidence/` | Evidence logging |
| `monitoring/` | File-system and process monitoring |
| `response/` | Threat response and containment |
| `simulator/` | Ransomware-like activity simulation |
| `tests/` | Automated test cases |
| `ui/` | User interface components |
| `config.json` | Application configuration |
| `main.py` | Main application entry point |
| `requirements.txt` | Python dependencies |

## Testing and Evaluation

Testing is an important part of evaluating CanaryGuard's behavior. The project includes automated tests and a simulation component for controlled evaluation.

Testing should be conducted in an isolated, authorized environment. Test results should be reviewed to assess detection behavior, expected responses, and potential limitations.


       ## Team Information:  full names and CTC IDs
1,  Haymanot Matebe : CTC-156-26
2, Teklu Kidanemaryam: CTC-4826-26
3, Surafel Habtewold :CTC-287-26
4, Marta Kefale : CTC-1772-26
5, Ferid Yusuf :CTC-1594-26
6, Rebira Likisa :CTC-1864-26
