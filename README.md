# EscalationOfPrivileges
THIS IS A MEMO APPLICATION using SwissCheese driver to achieve escalation of privileges - to add/enable the token privilege to load the dummy driver by bypassing KASLR.

To use this application, you need:
1. attach kernel debugger to your target
2. deploy and start swisscheese.sys driver
3. deploy dummy.sys driver (but do not start it)
4. use eop.exe to load dummy.sys
5. "sc query dummy" to check the dummy.sys status
6. you can use "sc stop dummy" to stop the dummy driver

To bypass KASLR, you need:
1. NtQuerySystemInformation to query system handle table and iterate the table to find what the required handle information
2. Use IOCTL to SwissCheese to add and enable token privilege (SeLoadDriverPrivilege) to the current process
3. Load/Unload the driver


