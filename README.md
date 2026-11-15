

This is the ONLY free public Huawei tool with Kirin 990 support!

You can rebrand, flash and unlock(even Kirin 990's bootloader!) Huawei devices!

We support Kirin 620-990 5g SoCs (As of 2.4.2, excluding 990 4g)!

# 
# Credits:

[TASZK Security Labs SL](https://taszk.io) for the head resend bootrom exploit

[kasnria001](https://github.com/kasnria001) for decrypted xloaders and LOTS of help in general

---

## Lock diagnostic (read-only)

`Device Information` → `Lock Diagnostic` runs a read-only inspection of the lock
records. It reads `oem lock-state info`, the `USRKEY`/`FBLOCK` NV items, dumps
`oeminfo`, `nvme` and `fastboot` with `oem dump-emmc`, parses the OEM_INFO
entries (`0x5c`, `0x5d`, `0x82`), verifies the USERLOCK HMAC of `0x5d` with
`USRKEY`, and compares the dumped `fastboot` image against the `FASTBOOT` block
of an `UPDATE.APP` and/or a signed factory `fastboot.img`.

The dumps require the factory fastboot loaded through VCOM; with the stock
fastboot they will fail. The diagnostic does not write any partition.

---

*NOTICE: This tool is an independent software product and has not been authorized, sponsored, or otherwise approved by Huawei Technologies Co., Ltd. HiSilicon and Kirin are trademarks of Huawei Technologies Co., Ltd. All product and company names are trademarks™ or registered® trademarks of their respective holders. Use of them does not imply any affiliation with or endorsement by them.*
