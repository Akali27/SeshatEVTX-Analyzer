using SeshatEVTXAnalyzer;
using System;
using System.Threading.Tasks;

namespace SeshatEVTXAnalyzer
{
    public static class EvtxAnalysisService
    {
        public static Task<AnalysisResult> RunAnalysisAsync(string[] evtxFiles, DateTime? startTime, DateTime? endTime)
        {
            if (evtxFiles == null || evtxFiles.Length == 0)
                throw new ArgumentException("No EVTX files were provided.");

            return Task.Run(() => EvtxAnalyzer.AnalyzeFiles(evtxFiles, startTime, endTime));
        }
    }
}