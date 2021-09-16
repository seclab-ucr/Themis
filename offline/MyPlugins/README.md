# My S2E Plugins

Installation
---
1. Clone the repo into <S2E_DIR>/source/s2e/libs2eplugins/src/s2e/Plugins/.
2. Add the .cpp files to libs2eplugins/src/CMakeLists.txt.
3. Rebuild S2E plugins. A quicker way is using the following command:
```
# Release version
cd <S2E_DIR>/build/libs2e-release/x86_64-s2e-softmmu/ && make && install libs2e.so <S2E_DIR>/install/share/libs2e/libs2e-x86_64-s2e.so
# Debug version
cd <S2E_DIR>/build/libs2e-debug/x86_64-s2e-softmmu/ && make
```

Plugins
---
| Plugin             | Description |
| ------------------ | ----------- |
| SymTCP             | The main plugin that runs selective symbolic execution on TCP code base.  |
| MyExecutionMonitor | Used to hook addresses / edges / functions while running. |
| AddressDB          | Maintains a mapping from binary addresses in TCP to corresponding variables or functions. |
| MemRangeDetector   | Specify the address range of TCP. |
| MyTracer           | Print execution trace in log. |


