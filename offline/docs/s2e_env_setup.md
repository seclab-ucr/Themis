# S2E Environment Setup 

Install S2E: <http://s2e.systems/docs/s2e-env.html>
Set $S2E_DIR to the root folder of S2E. 

Download S2E Linux image:
`s2e image_build -d debian-9.2.1-x86_64`

Apply code changes to S2E and rebuild:
1. Copy the MyPlugins folder to $S2E_DIR/source/s2e/libs2eplugins/src/s2e/Plugins/.
2. Apply the patches `s2e-with-state-merging.patch` and `qemu-with-state-merging.patch` in the patches folder to $S2E_DIR/source/s2e and $S2E_DIR/source/qemu respectively.
3. Run `s2e build` to rebuild S2E.

Import S2E TCP projects in the projects folder:
`s2e import_project kernel44.tar.xz`

Setup QEMU bridge mode: 
1. Create tun/tap device if it does not exist. 
    mkdir /dev/net
    mknod /dev/net/tun c 10 200
2. Create a bridge interface.
    ip link add name qemubr0 type bridge
    ip addr add 192.168.100.1/24 dev qemubr0
    ip link set qemubr0 up
3. Create a bridge.conf file under $S2E_DIR/install/etc/qemu/ with the following content.
    allow qemubr0
4. Use setuid to give qemu-bridge-helper root privilege.
    sudo chown root:root $S2E_DIR/install/libexec/qemu-bridge-helper 
    sudo chmod u+s $S2E_DIR/install/libexec/qemu-bridge-helper

Run S2E:
1. Run ./launch.sh in the project folder.
2. Netcat will be listening on port 5555
3. Host IP: 192.168.100.1
4. Guest IP: 192.168.100.2
5. Use packet_sender.py to keep sending packets to 192.168.100.2:5555 from host. 
    sudo ./packet_sender.py -p <payload length>

Notes:
- If want to use multiprocessing, modify "export S2E_MAX_PROCESSES=1" in launch.sh
- To debug S2E with gdb, run “./launch-s2e.sh debug”
- A quicker way to rebuild plugins is using the following commands:
    \# Release version
    cd $S2E_DIR/build/libs2e-release/x86_64-s2e-softmmu/ && make && install libs2e.so $S2E_DIR/install/share/libs2e/libs2e-x86_64-s2e.so
    \# Debug version
    cd $S2E_DIR/build/libs2e-debug/x86_64-s2e-softmmu/ && make

