# Finding discrepancies between TCP implementations using S2E

## Setup

- To setup S2E for the first time, see [here](s2e_env_setup.md)
- Build and copy S2E images to $S2E_DIR/images/
- Import S2E projects using s2e import_project command
- Apply patches and copy MyPlugins to S2E and rebuild S2E (see the S2E setup doc)
- Install Z3 Solver (Python): https://github.com/Z3Prover/z3. (pip install z3-solver)
- Make sure the qemu bridge interface has been properly setup (see the S2E setup doc)

## Experiment

- Label critical accept / drop points in TCP by add / Modify the accept / drop points in s2e-config.lua. A few examples of accept / drop points:
    - TCP LISTEN -> SYN_RECV state (accept)
    - TCP SYN_RECV -> ESTABLISHED state (accept)
    - Drop points where packets get dropped. etc.
- Basically we want to label accept / drop points that exist in both kernel versions and may contain discrepancies. 
- Change the symbolicPacketCounter in s2e-config.lua. It means the number of symbolic packets we are going to handle. For example, if we want to reach SYN_RECV state, we only need to send 1 packet; if we want to reach ESTABLISHED state, we need to send 2 packets. 
- Run S2E with launch-s2e.sh in the project folder. There should be a GUI window. Wait until nc has started in the guest OS. 
- Run packet_sender.py to send packets. It will keep sending packets to the port that nc listens to. Do not send packets before nc has fully started.
- S2E should finish after a while. Currently I have disabled TCP options in s2e-config.lua and in packet_sender.py. Otherwise, it will not finish. 
- The generated log files and results are in s2e-output and s2e-last folder. (Everything we need is in debug.txt)
- Use get_concrete_examples.py from s2e-tcp repo to collect the results from S2E
- Use z3differ.py to compare two different implementations. In z3differ.py, it first reads from two concrete example files, and generates two huge combined constraints and then compares them with Z3. Need to modify z3differ.py to make it combine constraints based on two sets of paths (examples) reaching the same labelled accept / drop points. 
- Find out how large a path group Z3 can handle. A larger group means more paths (examples) in the combined constraints, and more complexed constraints. 

