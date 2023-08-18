# RegReEPer 
## Reg Restore Evasion and Persistence
This short C code presents a Proof of Concept (POC) designed to achieve persistence and evade Sysmon event monitoring for registry actions such as key creation, update, and deletion, specifically targeting the REG_NOTIFY_CLASS Registry Callback in the Sysmon driver filter. To bypass monitoring, the POC leverages the RegSaveKeyExW() and RegRestoreKeyW() APIs, which are not included (as of writing) in sysmon monitoring or in REG_NOTIFY_CLASS type of registry callback of Sysmon driver filter.

By utilizing these APIs, the POC can create backups of registry keys using RegSaveKeyExW() and later restore them using RegRestoreKeyW(), effectively evading detection by Sysmon. It's essential to recognize that this POC serves only as a demonstration of a potential technique for achieving persistence and evading monitoring and should be used solely for educational or research purposes, refraining from any malicious intent or illegal activities.
