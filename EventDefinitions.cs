using System;
using System.Collections.Generic;

namespace SeshatEVTXAnalyzer
{
    public static class EventDefinitions
    {
        // - Event ID Lists - 
        public static readonly HashSet<int> FileAccessIds = new() { 4663, 4656, 4658, 4660, 4670, 5140, 5142, 5144, 5145 };
        public static readonly HashSet<int> UsbIds = new() { 20001, 2100, 2102, 2003, 400, 410, 1006, 1010, 3003, 3100, 3102, 6416, 6421, 6422, 6424 };
        public static readonly HashSet<int> DeviceInfoIds = new() { 1006, 1010, 20001, 2100, 2102, 2003, 6416, 6421, 6422, 6424, 400, 410 };
        public static readonly HashSet<int> NetworkIds = new() { 5156, 5158, 5152, 5154 };
        public static readonly HashSet<int> RemoteAccessIds = new() { 624, 4624, 4625, 4634, 4647, 4776, 4648, 4800, 4801, 4778, 4779, 1149 };
        public static readonly HashSet<int> PrivEscIds = new() { 4672, 4697, 4720, 4732, 4728, 4616, 4726 };
        public static readonly HashSet<int> AntiForensicsIds = new() { 1102, 104 };
        public static readonly HashSet<int> PowerShellIds = new() { 4104, 4103 };
        public static readonly HashSet<int> EmailTrustIds = new() { 4107, 4110 };

        public static readonly HashSet<int> AllInterestingIds = new();

        static EventDefinitions()
        {
            AllInterestingIds.UnionWith(FileAccessIds);
            AllInterestingIds.UnionWith(UsbIds);
            AllInterestingIds.UnionWith(DeviceInfoIds);
            AllInterestingIds.UnionWith(NetworkIds);
            AllInterestingIds.UnionWith(RemoteAccessIds);
            AllInterestingIds.UnionWith(PrivEscIds);
            AllInterestingIds.UnionWith(AntiForensicsIds);
            AllInterestingIds.UnionWith(PowerShellIds);
            AllInterestingIds.UnionWith(EmailTrustIds);
            AllInterestingIds.Add(4688);
        }

        public static readonly Dictionary<int, string> EventDescriptions = new()
        {
            {4663, "File/folder access attempt"}, {4656, "Handle to object requested"}, {4658, "Handle to object closed"},
            {4660, "Object deleted"}, {4670, "Permissions on object changed"}, {5140, "Access to a network share"},
            {5142, "Network share added"}, {5144, "Network share deleted"}, {5145, "Network share checked for access"},
            {20001, "USB device connected (DriverFrameworks-UserMode)"}, {2100, "USB device removed"},
            {2102, "USB device removal requested"}, {2003, "USB device configured/removed"},
            {400, "Device install (Kernel-PnP)"}, {410, "Device install (Kernel-PnP)"},
            {1006, "Storage/volume interaction"}, {1010, "Storage/volume interaction"},
            {3003, "Device configured"}, {3100, "Device started"}, {3102, "Device removed"},
            {6416, "New external device recognized"}, {6421, "PNP: Device enable requested"},
            {6422, "PNP: Device disable requested"}, {6424, "PNP: Device property change"},
            {5156, "Allowed outbound network connection"}, {5158, "TCP connection bind"},
            {5152, "Blocked connection"}, {5154, "Allowed connection"},
            {624, "Legacy logon/account event"}, {4624, "Successful logon"}, {4625, "Failed logon"},
            {4634, "Logoff"}, {4647, "User-initiated logoff"}, {4776, "Credential validation"},
            {4648, "Logon using explicit credentials"}, {4800, "Workstation locked"}, {4801, "Workstation unlocked"},
            {4778, "RDP session reconnected"}, {4779, "RDP session disconnected"}, {1149, "Successful RDP authentication"},
            {4672, "Special privileges assigned to new logon"}, {4697, "Service installed"},
            {4720, "User account created"}, {4732, "User added to local group"},
            {4728, "User added to privileged/AD group"}, {4616, "System time changed"}, {4726, "User account deleted"},
            {1102, "Security audit log cleared"}, {104, "System event log cleared"},
            {4104, "PowerShell script block logged"}, {4103, "PowerShell command logged"},
            {4107, "Certificate / trust error (Outlook/WinTrust)"}, {4110, "Certificate / trust chain issue"}
        };

        public static readonly string[] CloudProcessNames = { "OneDrive.exe", "Dropbox.exe", "GoogleDriveFS.exe", "Box.exe", "rclone.exe", "winscp.exe", "filezilla.exe" };
        public static readonly string[] EmailClientProcessNames = { "OUTLOOK.EXE", "thunderbird.exe" };
    }
}