using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SeshatEVTXAnalyzer
{
    public static class ReportGenerator
    {
        public static void GenerateCsvOutputs(string outputDir, List<TimelineEntry> filtered, List<FullLogEntry> all)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

                string filteredPath = Path.Combine(outputDir, $"Filtered_Timeline_{timestamp}.csv");
                using (var sw = new StreamWriter(filteredPath))
                {
                    sw.WriteLine("Time,EventID,Description,Provider");
                    foreach (var entry in filtered.OrderByDescending(x => x.Time))
                    {
                        sw.WriteLine($"{Escape(entry.Time.ToString("yyyy-MM-dd HH:mm:ss"))},{entry.EventId},{Escape(entry.Description)},{Escape(entry.Provider)}");
                    }
                }

                string allPath = Path.Combine(outputDir, $"All_Events_{timestamp}.csv");
                using (var sw = new StreamWriter(allPath))
                {
                    sw.WriteLine("Time,EventID,Source / Task Category");
                    foreach (var entry in all.OrderByDescending(x => x.Time))
                    {
                        sw.WriteLine($"{Escape(entry.Time.ToString("yyyy-MM-dd HH:mm:ss"))},{entry.EventId},{Escape(entry.SourceOrCategory)}");
                    }
                }
            }
            catch { }
        }

        private static string Escape(string? str)
        {
            if (string.IsNullOrEmpty(str)) return "";
            if (str.Contains(",") || str.Contains("\"") || str.Contains("\n") || str.Contains("\r"))
            {
                return "\"" + str.Replace("\"", "\"\"") + "\"";
            }
            return str;
        }
    }
}