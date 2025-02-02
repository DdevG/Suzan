## Disclaimer

**WARNING:** This tool is provided for educational and research purposes only.  
The vulnerability detection methods in **Suzan** are heuristic and may not capture every potential security issue. **Suzan** is **not** intended to be used for any malicious activities—it is designed solely to provide a broad view of blockchain contract security. Do not use this tool as the sole means of evaluating the security of a smart contract in a production environment.  
Always conduct a thorough manual review and use multiple security auditing tools before deploying any smart contract in production.



**Suzan** is a comprehensive Ethereum/EVM contract scanner and vulnerability analysis tool. It performs advanced static analysis of contract bytecode (and optionally Solidity source code via external tools like Slither) to detect common vulnerability patterns in smart contracts. The tool features a dynamic dashboard built with Flask, Plotly, and DataTables, providing real-time monitoring, analytics, and a live blockchain activity feed.

![Dashboard](https://github.com/user-attachments/assets/3e9b909b-2ab7-4e30-b544-9efb5e057973)

## Features

- **Comprehensive Vulnerability Analysis**  
  Suzan thoroughly tests for a range of potential vulnerabilities, including:
  - Re-Entrancy
  - Arithmetic Overflow and Underflow
  - Self Destruct
  - Accessing Private Data
  - Delegatecall
  - Source of Randomness
  - Denial of Service
  - Phishing with tx.origin
  - Hiding Malicious Code with External Contract
  - Honeypot
  - Front Running
  - Block Timestamp Manipulation
  - Signature Replay
  - Bypass Contract Size Check
  - Deploy Different Contracts at Same Address
  - Vault Inflation Attack
  - WETH Permit
  - 63 / 64 Gas Rule

  Suzan uses multiple heuristic methods (including opcode pattern matching, keyword searches, and checks for specific opcodes) to detect these vulnerabilities.


- **Dynamic Dashboard & Analytics**  
  - **Real-Time Updates:** The dashboard updates every 5 seconds, displaying a summary graph, aggregated vulnerability counts, and a live activity feed.
  - **Interactive Charts:** View detailed analytics with interactive pie and bar charts built with Plotly.
  - **DataTables Integration:** Tables support filtering, pagination, and smooth scrolling.

  ![Analytics](https://github.com/user-attachments/assets/bc7023d9-668a-4e6f-bc59-39e3ce688a39)
  ![RiskRating](https://github.com/user-attachments/assets/23586185-cae0-4954-b488-49201d772dda)

- **Live Blockchain Feed**  
  Continuously polls the Sonic EVM-compatible blockchain for new blocks and transactions, scanning discovered contract addresses in real time.

![LiveFeed](https://github.com/user-attachments/assets/d6b0dfe5-68af-4214-8715-3bf965119769)

## Installation

### Prerequisites

- **Python 3.x**  
- The following Python packages:
  - Flask
  - plotly
  - web3
  - Werkzeug

Login:
admin
password

Install the required packages using pip:

```bash
pip install Flask plotly web3 Werkzeug


python suzan.py

