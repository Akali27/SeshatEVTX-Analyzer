# Seshat EVTX Analyzer
Taking its name from Seshat, the ancient Egyptian goddess of wisdom and record-keeping, this application provides a focused EVTX forensic analysis capability designed to identify indicators of data exfiltration and support fast, reliable investigative workflows.
The analyzer can ingest any .evtx file, including less reviewed logs located in: C:\Windows\System32\winevt\Logs\

It produces a clear analytic report and structured CSV exports, including a filtered timeline of exfiltration-relevant events and a complete list of all parsed events. This enables rapid triage, deeper manual review, and seamless export into SIEM tools, spreadsheets, or case documentation.

## Features
- Support for all EVTX logs beyond Application, System, Security, and Setup
- Date and time range filtering
- Noise reduction to hide high-frequency, low-value events (e.g., service logons, SYSTEM activity)
- Categorized forensic timeline generation
- CSV export for filtered events and full event listings

## Getting Started
### Dependencies
.NET Runtime — .NET 6.0 or later

### Installation & Usage 
Ensure a copy of the EVTX logs you want to analyze are accessible. 

After downloading the latest release from the Releases page: 
1- Launch the .exe file.
2- Click Select EVTX Files and choose one or more logs.
3- (Optional) Set a Start Time and End Time for timestamp filtering.
4- Click Run Analysis.

## Help
If the application fails to parse a file:
- Ensure the EVTX file is not corrupted
- Make sure the log was exported correctly from the source machine
- If timestamps look incorrect, verify system timezone settings

## Version History
1.0 — Initial Release

## Roadmap
Future versions will focus on:
- Refined filtering logic to further reduce noise
- More advanced detection heuristics for data exfiltration patterns
- Optimized categorization guided by real-world forensic cases
- Enhanced reporting templates

## Feedback
Under issues, list which EventID's you want filtered for noise reduction. 
