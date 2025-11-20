using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SeshatEVTXAnalyzer
{
    public static class EvtxAnalyzer
    {
        private static readonly Regex VidPidRegex = new(@"VID_([0-9A-Fa-f]{4}).*PID_([0-9A-Fa-f]{4})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex VolumeGuidRegex = new(@"Volume\{[0-9A-Fa-f\-]+\}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex ContainerIdRegex = new(@"Container ID:\s*\{([0-9A-Fa-f\-]+)\}", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static AnalysisResult AnalyzeFiles(IEnumerable<string> evtxPaths, DateTime? startTime, DateTime? endTime)
        {
            var result = new AnalysisResult();
            var sb = new StringBuilder();

            // Stats containers
            var fileAccessStats = new Dictionary<int, int>();
            var usbStats = new Dictionary<int, int>();
            var networkStats = new Dictionary<int, int>();
            var remoteAccessStats = new Dictionary<int, int>();
            var privEscStats = new Dictionary<int, int>();
            var antiForensicsStats = new Dictionary<int, int>();
            var psStats = new Dictionary<int, int>();
            var emailTrustStats = new Dictionary<int, int>();

            var deviceInfoByEvent = new Dictionary<int, HashSet<string>>();
            var usbDevices = new Dictionary<string, UsbDeviceInfo>(StringComparer.OrdinalIgnoreCase);

            var cloudProcessCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var emailProcessCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int powershellEncodedCount = 0;

            var observedComputers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var observedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var failedProviders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var logSummarySb = new StringBuilder();

            logSummarySb.AppendLine("                                        ================================================================");
            logSummarySb.AppendLine("                                             \\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\  — INDIVIDUAL LOG FILE SUMMARY —  /\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/");
            logSummarySb.AppendLine("                                        ================================================================");
            logSummarySb.AppendLine();

            foreach (var evtxPath in evtxPaths)
            {
                if (!File.Exists(evtxPath)) { logSummarySb.AppendLine($"[!] File not found: {evtxPath}"); continue; }
                var fileName = Path.GetFileName(evtxPath).ToUpperInvariant();

                logSummarySb.AppendLine("----------------------------------------------------------------------");
                logSummarySb.AppendLine($" File: {fileName}");
                logSummarySb.AppendLine("----------------------------------------------------------------------");

                try
                {
                    var query = new EventLogQuery(evtxPath, PathType.FilePath);
                    using var reader = new EventLogReader(query);
                    int totalCount = 0;
                    var perFileIdCounts = new Dictionary<int, int>();
                    var exfilCountsThisFile = new Dictionary<int, int>();
                    EventRecord? record;

                    while ((record = reader.ReadEvent()) != null)
                    {
                        if (record.TimeCreated.HasValue)
                        {
                            var t = record.TimeCreated.Value.ToLocalTime();
                            if (startTime.HasValue && t < startTime.Value) continue;
                            if (endTime.HasValue && t > endTime.Value) continue;
                        }
                        else { continue; }

                        if (!string.IsNullOrEmpty(record.MachineName)) observedComputers.Add(record.MachineName);

                        int id = record.Id;
                        DateTime time = record.TimeCreated.Value.ToLocalTime();
                        string provider = record.ProviderName ?? "Unknown";

                        string column3Data = provider;
                        if (string.Equals(record.LogName, "Security", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                string task = record.TaskDisplayName;
                                if (!string.IsNullOrEmpty(task)) column3Data = task;
                            }
                            catch { column3Data = "Security"; }
                        }

                        result.FullLogData.Add(new FullLogEntry
                        {
                            Time = time,
                            EventId = id,
                            SourceOrCategory = column3Data
                        });

                        bool isNoise = false;
                        if (id == 4624) ExtractUserAndCheckNoise(record, observedUsers, out isNoise);
                        else if (id == 4672) isNoise = CheckNoise4672(record);

                        if (isNoise) continue;

                        totalCount++;
                        Increment(perFileIdCounts, id);

                        string rawMsg = "";
                        if (EventDefinitions.AllInterestingIds.Contains(id))
                        {
                            rawMsg = SafeFormatDescription(record, provider, failedProviders);
                        }

                        CategorizeEvent(record, id, provider, rawMsg, time,
                            fileAccessStats, usbStats, networkStats, remoteAccessStats,
                            privEscStats, antiForensicsStats, psStats, emailTrustStats,
                            cloudProcessCounts, emailProcessCounts, deviceInfoByEvent, usbDevices,
                            result.TimelineData, exfilCountsThisFile, ref powershellEncodedCount);
                    }

                    logSummarySb.AppendLine("[ File Summary ]");
                    logSummarySb.AppendLine($"  Total processed events: {totalCount}\n");

                    var exfilRelevant = exfilCountsThisFile.OrderByDescending(kv => kv.Value).ToList();
                    if (exfilRelevant.Count > 0)
                    {
                        logSummarySb.AppendLine("[ Events of Forensic Interest ]");
                        foreach (var kv in exfilRelevant)
                        {
                            var desc = EventDefinitions.EventDescriptions.TryGetValue(kv.Key, out var d) ? d : "Unknown/other";
                            AppendEventLine(logSummarySb, kv.Key, kv.Value, desc);
                        }
                    }
                    logSummarySb.AppendLine();
                }
                catch (Exception ex) { logSummarySb.AppendLine($"[ ERROR ] {evtxPath}: {ex.Message}\n"); }
            }

            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine(" System Information");
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine($"  [ Computers Identified ({observedComputers.Count}) ]");
            if (observedComputers.Count > 0) foreach (var c in observedComputers) sb.AppendLine($"   - {c}");
            else sb.AppendLine("   - None identified");

            sb.AppendLine();
            sb.AppendLine($"  [ User Accounts Observed (via Logon Events) ({observedUsers.Count}) ]");
            if (observedUsers.Count > 0) foreach (var u in observedUsers.OrderBy(u => u)) sb.AppendLine($"   - {u}");
            else sb.AppendLine("   - None identified (or no 4624 events found)");
            sb.AppendLine();
            sb.AppendLine();

            sb.Append(logSummarySb.ToString());

            sb.AppendLine("                                        ================================================================");
            sb.AppendLine("                                             \\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\  — CATEGORY SUMMARY —   \\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/");
            sb.AppendLine("                                        ================================================================");
            sb.AppendLine();

            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "File Access / Deletion / Network Shares", fileAccessStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "USB / Removable Media Activity", usbStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "Network Activity (Firewall)", networkStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "Remote Access / Logon / RDP", remoteAccessStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "Privilege Escalation / Account Changes", privEscStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "Anti-Forensics / Log Tampering", antiForensicsStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "PowerShell / Scripted Activity", psStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            PrintCategory(sb, "Email Trust / Certificate Issues", emailTrustStats, deviceInfoByEvent);
            sb.AppendLine();
            sb.AppendLine("----------------------------------------------------------------------");
            sb.AppendLine();

            sb.AppendLine("[ USB Device Overview (Removable Storage Only) ]");
            if (usbDevices.Count == 0) { sb.AppendLine("  No external removable storage devices identified."); }
            else
            {
                foreach (var kv in usbDevices.OrderByDescending(k => k.Value.Count))
                {
                    var info = kv.Value;
                    sb.AppendLine($"  Device: {kv.Key}");
                    sb.AppendLine($"    Events: {info.Count}");
                    if (info.FirstSeen.HasValue && info.LastSeen.HasValue)
                        sb.AppendLine($"    First Seen: {info.FirstSeen.Value:yyyy-MM-dd HH:mm:ss}  |  Last Seen: {info.LastSeen.Value:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine();
                }
            }
            sb.AppendLine();

            if (cloudProcessCounts.Count > 0 || emailProcessCounts.Count > 0 || powershellEncodedCount > 0)
            {
                sb.AppendLine("[ PROCESS-BASED EXFILTRATION INDICATORS (4688 / 4104) ]");
                foreach (var kv in cloudProcessCounts.OrderByDescending(k => k.Value)) sb.AppendLine($"    {kv.Key,-25} {kv.Value} process creation events");
                foreach (var kv in emailProcessCounts.OrderByDescending(k => k.Value)) sb.AppendLine($"    {kv.Key,-25} {kv.Value} process creation events");
                if (powershellEncodedCount > 0) sb.AppendLine($"\n  PowerShell -EncodedCommand usage: {powershellEncodedCount} events.");
                sb.AppendLine();
            }

            sb.AppendLine();
            sb.AppendLine("                                        ================================================================");
            sb.AppendLine("                                             /\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\  — TIMELINE —  /\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/");
            sb.AppendLine("                                        ================================================================");
            sb.AppendLine();
            if (result.TimelineData.Count == 0) sb.AppendLine("  No timeline-relevant events found in loaded logs.");
            else
            {
                foreach (var entry in result.TimelineData.OrderByDescending(t => t.Time))
                {
                    string timeStr = entry.Time.ToString("yyyy-MM-dd HH:mm:ss");
                    string descPart = string.IsNullOrWhiteSpace(entry.Description) ? "" : $" ({entry.Description})";
                    sb.AppendLine($"  {timeStr}  -  ID {entry.EventId}{descPart}");
                }
            }
            sb.AppendLine();

            result.ReportText = sb.ToString();
            return result;
        }

        private static void ExtractUserAndCheckNoise(EventRecord record, HashSet<string> users, out bool isNoise)
        {
            isNoise = false;
            string xml;
            try { xml = record.ToXml(); } catch { return; }
            if (string.IsNullOrWhiteSpace(xml)) return;

            try
            {
                var doc = XDocument.Parse(xml);
                var dataNodes = doc.Descendants().Where(e => e.Name.LocalName == "Data").Where(d => d.Attribute("Name") != null).ToList();

                var logonType = dataNodes.FirstOrDefault(d => string.Equals((string)d.Attribute("Name"), "LogonType", StringComparison.OrdinalIgnoreCase));
                if (logonType != null && ((string)logonType).Trim() == "5") { isNoise = true; return; }

                var targetUser = dataNodes.FirstOrDefault(d => string.Equals((string)d.Attribute("Name"), "TargetUserName", StringComparison.OrdinalIgnoreCase));
                if (targetUser != null)
                {
                    string u = ((string)targetUser).Trim();
                    if (!string.IsNullOrEmpty(u) &&
                        !u.EndsWith("$") &&
                        !u.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                        !u.StartsWith("DWM-", StringComparison.OrdinalIgnoreCase) &&
                        !u.StartsWith("UMFD-", StringComparison.OrdinalIgnoreCase) &&
                        !u.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
                        !u.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) &&
                        !u.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase))
                    {
                        users.Add(u);
                    }
                }
            }
            catch { }
        }

        private static bool CheckNoise4672(EventRecord record)
        {
            string xml;
            try { xml = record.ToXml(); } catch { return false; }
            if (string.IsNullOrWhiteSpace(xml)) return false;
            try
            {
                var doc = XDocument.Parse(xml);
                var dataNodes = doc.Descendants().Where(e => e.Name.LocalName == "Data").Where(d => d.Attribute("Name") != null).ToList();
                var subjectSid = dataNodes.FirstOrDefault(d => string.Equals((string)d.Attribute("Name"), "SubjectUserSid", StringComparison.OrdinalIgnoreCase));
                if (subjectSid != null && string.Equals(((string)subjectSid).Trim(), "S-1-5-18", StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { }
            return false;
        }

        private static string SafeFormatDescription(EventRecord record, string provider, HashSet<string> failedProviders)
        {
            if (failedProviders.Contains(provider)) return "";
            try { return record.FormatDescription() ?? string.Empty; }
            catch { failedProviders.Add(provider); return ""; }
        }

        private static bool IsTrulyExternalStorage(string msg, string provider)
        {
            if (string.IsNullOrWhiteSpace(msg)) return false;
            if (msg.IndexOf("ACPI", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("ROOT", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("UEFI", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("Display", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("MMDEVAPI", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("HID", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("input.inf", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("BTH", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("bthusb", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("NET", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("wbfusbdriver", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (msg.IndexOf("print", StringComparison.OrdinalIgnoreCase) >= 0) return false;

            bool hasStorageKeyword = msg.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("usbstor.inf", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("UASPSTOR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("Disk", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("Volume", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("Mass Storage", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     msg.IndexOf("{36fc9e60-c465-11cf-8056-444553540000}", StringComparison.OrdinalIgnoreCase) >= 0;

            bool isStorageProvider = provider.Contains("Partition", StringComparison.OrdinalIgnoreCase) ||
                                     provider.Contains("Storage-ClassPnP", StringComparison.OrdinalIgnoreCase);

            return hasStorageKeyword || isStorageProvider;
        }

        private static void Increment(Dictionary<int, int> dict, int key) { if (!dict.ContainsKey(key)) dict[key] = 0; dict[key]++; }
        private static void Increment(Dictionary<string, int> dict, string key) { if (!dict.ContainsKey(key)) dict[key] = 0; dict[key]++; }

        private static void AppendEventLine(StringBuilder sb, int id, int count, string? description)
        {
            string idPart = $"ID {id}";
            string countPart = $"{count} events";
            string descPart = (string.IsNullOrWhiteSpace(description) || description == "Unknown/other") ? string.Empty : $"({description})";
            const int dottedFieldTargetWidth = 32;
            var line = new StringBuilder();
            line.Append("  "); line.Append(idPart); line.Append(' ');
            int currentLen = line.Length;
            int dotCount = Math.Max(3, dottedFieldTargetWidth - currentLen);
            line.Append('.', dotCount); line.Append(' '); line.Append(countPart);
            if (!string.IsNullOrEmpty(descPart)) { line.Append("   "); line.Append(descPart); }
            sb.AppendLine(line.ToString());
        }

        private static void PrintCategory(StringBuilder sb, string title, Dictionary<int, int> stats, Dictionary<int, HashSet<string>> deviceInfoByEvent)
        {
            sb.AppendLine($"[ {title} ]");
            if (stats.Count == 0) { sb.AppendLine("  No matching events found in loaded logs."); sb.AppendLine(); return; }
            foreach (var kv in stats.OrderByDescending(k => k.Value))
            {
                var desc = EventDefinitions.EventDescriptions.TryGetValue(kv.Key, out var d) ? d : "Unknown/other";
                AppendEventLine(sb, kv.Key, kv.Value, desc);
                if (deviceInfoByEvent.TryGetValue(kv.Key, out var examples) && examples.Count > 0)
                {
                    foreach (var ex in examples) { sb.AppendLine($"    e.g., {ex}"); }
                }
            }
        }

        private static void CategorizeEvent(EventRecord record, int id, string provider, string msg, DateTime time,
            Dictionary<int, int> fileAccessStats, Dictionary<int, int> usbStats, Dictionary<int, int> networkStats,
            Dictionary<int, int> remoteAccessStats, Dictionary<int, int> privEscStats, Dictionary<int, int> antiForensicsStats,
            Dictionary<int, int> psStats, Dictionary<int, int> emailTrustStats,
            Dictionary<string, int> cloudProcessCounts, Dictionary<string, int> emailProcessCounts,
            Dictionary<int, HashSet<string>> deviceInfoByEvent, Dictionary<string, UsbDeviceInfo> usbDevices,
            List<TimelineEntry> timelineEntries, Dictionary<int, int> exfilCountsThisFile, ref int powershellEncodedCount)
        {
            bool msgLoaded = !string.IsNullOrEmpty(msg);
            bool isUsbRaw = EventDefinitions.UsbIds.Contains(id) && IsUsbProvider(provider);
            bool is4688or4104 = (id == 4688 || id == 4104);
            bool isDeviceInfo = EventDefinitions.DeviceInfoIds.Contains(id) && IsUsbProvider(provider);

            bool isFileAccess = EventDefinitions.FileAccessIds.Contains(id) && provider.Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase);
            bool isNetwork = EventDefinitions.NetworkIds.Contains(id) && provider.Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase);
            bool isRemoteAccess = false;
            if (EventDefinitions.RemoteAccessIds.Contains(id))
            {
                if (id == 1149) isRemoteAccess = provider.IndexOf("TerminalServices", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("RemoteConnectionManager", StringComparison.OrdinalIgnoreCase) >= 0;
                else isRemoteAccess = provider.Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase);
            }
            bool isPrivEsc = EventDefinitions.PrivEscIds.Contains(id) && provider.Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase);
            bool isAntiForensics = false;
            if (id == 1102) isAntiForensics = provider.Equals("Microsoft-Windows-Security-Auditing", StringComparison.OrdinalIgnoreCase);
            else if (id == 104) isAntiForensics = provider.Equals("Microsoft-Windows-Eventlog", StringComparison.OrdinalIgnoreCase);
            bool isPs = EventDefinitions.PowerShellIds.Contains(id) && provider.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase) >= 0;
            bool isEmailTrust = EventDefinitions.EmailTrustIds.Contains(id) && (provider.IndexOf("CAPI", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("Certificate", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("Crypto", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("WinTrust", StringComparison.OrdinalIgnoreCase) >= 0);

            bool isFocusedCategory = isFileAccess || isUsbRaw || isNetwork || isRemoteAccess || isPrivEsc || isAntiForensics || isPs || isEmailTrust;

            if (isFileAccess) Increment(fileAccessStats, id);
            if (isUsbRaw) Increment(usbStats, id);
            if (isNetwork) Increment(networkStats, id);
            if (isRemoteAccess) Increment(remoteAccessStats, id);
            if (isPrivEsc) Increment(privEscStats, id);
            if (isAntiForensics) Increment(antiForensicsStats, id);
            if (isPs) Increment(psStats, id);
            if (isEmailTrust) Increment(emailTrustStats, id);

            if (isFocusedCategory) Increment(exfilCountsThisFile, id);

            if (isDeviceInfo && msgLoaded && IsTrulyExternalStorage(msg, provider))
            {
                if (!string.IsNullOrWhiteSpace(msg))
                {
                    if (!deviceInfoByEvent.TryGetValue(id, out var set)) { set = new HashSet<string>(); deviceInfoByEvent[id] = set; }
                    if (set.Count < 3)
                    {
                        string trimmed = msg.Length > 200 ? msg.Substring(0, 200) + "..." : msg;
                        set.Add(trimmed);
                    }
                }
            }

            if (isUsbRaw && msgLoaded && IsTrulyExternalStorage(msg, provider))
            {
                var vidPids = new List<string>();
                var volumes = new List<string>();
                var containers = new List<string>();

                if (!string.IsNullOrEmpty(msg))
                {
                    foreach (Match m in VidPidRegex.Matches(msg))
                    {
                        if (m.Groups.Count >= 3)
                        {
                            string vid = m.Groups[1].Value.ToUpperInvariant();
                            string pid = m.Groups[2].Value.ToUpperInvariant();
                            vidPids.Add($"VID_{vid}&PID_{pid}");
                        }
                    }
                    foreach (Match m in VolumeGuidRegex.Matches(msg)) volumes.Add(m.Value);
                    foreach (Match m in ContainerIdRegex.Matches(msg))
                    {
                        if (m.Groups.Count >= 2) containers.Add(m.Groups[1].Value.ToUpperInvariant());
                    }
                }

                string key;
                if (vidPids.Count > 0) key = string.Join(", ", vidPids.Distinct());
                else if (volumes.Count > 0) key = string.Join(", ", volumes.Distinct());
                else if (containers.Count > 0) key = "Container " + string.Join(", ", containers.Distinct());
                else key = $"{provider} / ID {id}";

                if (!usbDevices.TryGetValue(key, out var info)) { info = new UsbDeviceInfo(); usbDevices[key] = info; }
                info.Count++;
                if (!info.FirstSeen.HasValue || time < info.FirstSeen.Value) info.FirstSeen = time;
                if (!info.LastSeen.HasValue || time > info.LastSeen.Value) info.LastSeen = time;

                foreach (var vp in vidPids) info.VidPids.Add(vp);
                foreach (var vol in volumes) info.VolumeGuids.Add(vol);
                foreach (var c in containers) info.ContainerIds.Add(c);
                if (!string.IsNullOrEmpty(msg) && info.SampleMessages.Count < 3)
                {
                    string trimmed = msg.Length > 200 ? msg.Substring(0, 200) + "..." : msg;
                    info.SampleMessages.Add(trimmed);
                }
            }

            if (isFocusedCategory)
            {
                string desc = EventDefinitions.EventDescriptions.TryGetValue(id, out var d) ? d : "";
                timelineEntries.Add(new TimelineEntry { Time = time, EventId = id, Description = desc, Provider = provider });
            }

            if (is4688or4104 && msgLoaded && !string.IsNullOrEmpty(msg))
            {
                foreach (var proc in EventDefinitions.CloudProcessNames) if (msg.IndexOf(proc, StringComparison.OrdinalIgnoreCase) >= 0) Increment(cloudProcessCounts, proc);
                foreach (var proc in EventDefinitions.EmailClientProcessNames) if (msg.IndexOf(proc, StringComparison.OrdinalIgnoreCase) >= 0) Increment(emailProcessCounts, proc);
                if (msg.IndexOf("-EncodedCommand", StringComparison.OrdinalIgnoreCase) >= 0) powershellEncodedCount++;
            }
        }

        private static bool IsUsbProvider(string provider)
        {
            if (string.IsNullOrEmpty(provider)) return false;
            return provider.IndexOf("Kernel-PnP", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("DriverFrameworks-UserMode", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("UserPnp", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("StorPort", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("USB", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("Volume", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("Partition", StringComparison.OrdinalIgnoreCase) >= 0 || provider.IndexOf("Disk", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}