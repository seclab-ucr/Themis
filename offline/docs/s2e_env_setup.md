# S2E Environment Setup 

## Steps

1. Install S2E following the instructions: <http://s2e.systems/docs/s2e-env.html>

2. Set $S2E_DIR to the root folder of S2E. 

3. Download the S2E Linux image: `s2e image_build -d debian-9.2.1-x86_64`

4. Apply code changes to S2E and rebuild:
    1. Copy _MyPlugins_ to $S2E_DIR/source/s2e/libs2eplugins/src/s2e/Plugins/.
    2. Apply the patches (i.e., _s2e-with-state-merging.patch_ and _qemu-with-state-merging.patch_) to $S2E_DIR/source/s2e and $S2E_DIR/source/qemu respectively.
    3. Rebuild S2E with `s2e build`.

5. Import S2E project: `s2e import_project kernel44.tar.xz`

6. Setup QEMU bridge mode: 
    1. Create tun/tap device if it does not exist. 
        ```
        mkdir /dev/net
        mknod /dev/net/tun c 10 200
        ```
    2. Create a bridge interface.
        ```
        ip link add name qemubr0 type bridge
        ip addr add 192.168.100.1/24 dev qemubr0
        ip link set qemubr0 up
        ```
    3. Create a _bridge.conf_ file under $S2E_DIR/install/etc/qemu/ with the following content.
        ```
        allow qemubr0
        ```
    4. Use setuid to give qemu-bridge-helper root privilege.
        ```
        sudo chown root:root $S2E_DIR/install/libexec/qemu-bridge-helper
        sudo chmod u+s $S2E_DIR/install/libexec/qemu-bridge-helper
        ```

7. Run S2E:
    1. Run `./launch.sh` in the project folder.
    2. Netcat will be listening on port 5555
    3. Host IP: 192.168.100.1
    4. Guest IP: 192.168.100.2
    5. Use _packet_sender.py_ to keep sending packets to 192.168.100.2:5555 from host. 
        ```
        sudo ./packet_sender.py -p <payload length>
        ```

    
## Notes:
- If want to use multiprocessing, change the `S2E_MAX_PROCESSES=1` in launch.sh
- To debug S2E with gdb, run `./launch-s2e.sh debug`
- A quicker way to rebuild plugins is using the following commands:
    ```
    # Release version
    cd $S2E_DIR/build/libs2e-release/x86_64-s2e-softmmu/ && make && install libs2e.so $S2E_DIR/install/share/libs2e/libs2e-x86_64-s2e.so
    # Debug version
    cd $S2E_DIR/build/libs2e-debug/x86_64-s2e-softmmu/ && make
    ```

