# IBM-QISKET-HACKATHON
# PQC Crypto Inventory & Migration Planner

An AST-based static code analysis tool written in C to detect classical cryptographic API usages (RSA, ECC, AES, SHA), evaluate quantum security risk against Shor's and Grover's algorithms, and suggest Post-Quantum Cryptography (PQC) replacements (ML-KEM, ML-DSA).

---

## Key Features

- **AST-Based Detection**: Uses **Tree-Sitter** AST parsing to accurately inspect syntax tree nodes rather than relying on standard regex/string matching.
- **Multi-Language Grammar Parsing**: Integrated native C parsers for **C**, **Python**, and **Java**.
- **Quantum Risk Mapping**:
  - **HIGH Risk**: RSA / ECC algorithms (vulnerable to Shor's algorithm). Suggests **ML-KEM** (key encapsulation) or **ML-DSA** (signatures).
  - **MODERATE Risk**: AES-128 (vulnerable to Grover's algorithm). Suggests **AES-256** or PQC schemes.
  - **LOWER Risk**: AES-256 / SHA-256 (quantum-resistant for near/mid-term).
- **Lightweight & Fast**: Pure C executable with low memory overhead and rapid scan execution times.

---

## System Requirements & Dependencies

- **GCC / Clang Compiler**
- **Tree-Sitter Core C Library** (`libtree-sitter`)
- **Git**

### Installing Dependencies

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install libtree-sitter-dev gcc make git

