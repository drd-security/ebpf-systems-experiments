# Challenge notes

## Anti-debugging

The anti-debugging experiment demonstrates how a kernel-resident BPF program can observe a debugging-related event associated with a target application and trigger a response.

## Write protection

The protected-file challenge attaches to an LSM file-open hook. It filters by process name, checks whether the inode is a regular file, inspects write mode, and returns `-EPERM` to deny the operation when the policy matches.

## Ciphered writes

The cipher challenge introduces shared configuration through maps so a userspace-supplied shift value can influence kernel-side processing.

## Fork-rate control

The fork experiment maintains state across process-creation events and compares creation timestamps to enforce a rate-limiting policy over recent children.

## Page-fault frequency

The PFF monitor keeps timestamp information for page faults and detects when the event rate leaves a configured range. The userspace component maintains a time window and receives notifications from the kernel through a perf buffer.
