using System;
using System.Collections.Generic;

namespace SeshatEVTXAnalyzer
{
    public class AnalysisResult
    {
        public string ReportText { get; set; } = "";
        public List<TimelineEntry> TimelineData { get; set; } = new();
        public List<FullLogEntry> FullLogData { get; set; } = new();
    }

    public class TimelineEntry
    {
        public DateTime Time { get; set; }
        public int EventId { get; set; }
        public string Description { get; set; } = "";
        public string Provider { get; set; } = "";
    }

    public class FullLogEntry
    {
        public DateTime Time { get; set; }
        public int EventId { get; set; }
        public string SourceOrCategory { get; set; } = "";
    }

    public class UsbDeviceInfo
    {
        public int Count;
        public DateTime? FirstSeen;
        public DateTime? LastSeen;
        public HashSet<string> VidPids = new();
        public HashSet<string> VolumeGuids = new();
        public HashSet<string> ContainerIds = new();
        public HashSet<string> SampleMessages = new();
    }
}