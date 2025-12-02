# go-gtp5gnl

go-gtp5gnl provides a netlink library about gtp5g for Go.

## ⚠️ IMPORTANT: Configuration Required Before Use

**WNC: Before building or using this library, you MUST generate a system-specific configuration file.**

This library requires kernel-specific parameters that vary by system. Run the detection script on your target system:

```bash
cd go-gtp5gnl
./scripts/detect_kernel_params.sh > go-gtp5gnl.yaml
```

**Why this is needed:**
- Different systems have different page sizes (4KB, 8KB, 16KB, 64KB)
- Kernel configurations vary (CONFIG_MAX_SKB_FRAGS can be 16, 17, 18, etc.)
- Using incorrect values causes netlink communication failures

**Verify your configuration:**
```bash
./scripts/detect_kernel_params.sh --verify
```

**For detailed instructions, see [CONFIG.md](CONFIG.md)**

## License

This software is released under the Apache 2.0 License, see LICENSE

## Usage

### WNC: Debug Mode

To enable debug logging and see configuration details:

```bash
export GTP5GNL_DEBUG=1

```

This will show:
- Which config file was loaded
- Detected kernel parameters (PAGE_SIZE, MAX_SKB_FRAGS, SKB_OVERHEAD, NLMSG_HDRLEN)
- Calculated netlink message sizes

### Command-line Tools

#### List all PDR/FAR/QER
```bash
# ./gtp5g-tunnel list [pdr/far/qer]
./gtp5g-tunnel list pdr
```

#### Get/Del/Add/Mod PDR/FAR/QER
```
# ./gtp5g-tunnel [get/del/add/mod] [PDR/FAR/QER] [interface_name] [seid] [id] [option]
./gtp5g-tunnel add pdr upfgtp0 1 3 --pcd 99
```
- options
    ```
    PDR OPTIONS

            --pcd <precedence>

            --hdr-rm <outer-header-removal>

            --far-id <existed-far-id>

            --ue-ipv4 <pdi-ue-ipv4>

            --f-teid <i-teid> <local-gtpu-ipv4>

            --sdf-desp <description-string>

            --sdf-tos-traff-cls <tos-traffic-class>

            --sdf-scy-param-idx <security-param-idx>

            --sdf-flow-label <flow-label>

            --sdf-id <id>

            --qer-id <id>

    FAR OPTIONS

            --action <apply-action>

            --hdr-creation <description> <o-teid> <peer-ipv4> <peer-port>

    QER OPTIONS

            --qer-id <qer-id>

            --qfi-id <qfi-id> [Value range: {0..63}]

            --rqi-d <rqi> [Value range: {0=not triggered, 1=triggered}]

            --ppp <ppp> [Value range: {0=not present, 1=present}]

            --ppi <ppi> [Value range: {0..7}]
    ```