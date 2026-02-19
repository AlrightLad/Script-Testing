DTC Network Assessment Toolkit
===============================

QUICK START:
1. Plug USB into client's server
2. Open PowerShell as Administrator
3. Navigate to this folder: cd D:\DTC-Assessment (or wherever the USB is mounted)
4. Run: .\Run-Assessment.ps1 -ClientName "Practice Name" -TechName "Your Name"
5. Report saves to the Output\ folder on this USB

OPTIONAL PARAMETERS:
  -HaloTicket "12345"                        — includes ticket number on the report
  -ScanWorkstations "10.0.1.50","10.0.1.51"  — spot-checks specified workstations
  -Verbose                                    — shows detailed progress for troubleshooting

REQUIREMENTS:
  - Must run as Administrator
  - Must run on the client's server (or a domain-joined workstation for partial data)
  - Windows Server 2016, 2019, or 2022

WHAT THIS TOOL COLLECTS:
  - Server hardware, OS, disk health
  - Network configuration, device count, gateway detection
  - Active Directory structure and health
  - All installed dental software (PMS, imaging, VoIP, backup, RMM, utilities)
  - Security posture (AV, firewall, shares, admin accounts)
  - Printer configuration
  - Gap analysis against DTC infrastructure standards

WHAT THIS TOOL DOES NOT COLLECT (tech documents manually):
  - Phone hardware (manufacturer, model, count) — document visually
  - Physical infrastructure (server room, cabling, UPS) — use AM Field Sheet
  - WiFi coverage — requires separate survey tool
  - Network switch port configurations — requires UniFi controller access
  - VoIP provider details and call tree — ask the client

OUTPUT:
  - PDF report: Output\[ClientName]_Assessment_[Date].pdf
  - Raw JSON data: Output\[ClientName]_RawData_[Date].json
  - Attach the PDF to the HALO ticket

TROUBLESHOOTING:
  - "Not running as Administrator" — right-click PowerShell, Run as Administrator
  - PDF generation failed — check that Lib\wkhtmltopdf.exe exists. If missing, the tool saves an HTML report instead.
  - AD data missing — if running on a workgroup machine, AD data is expected to be unavailable
  - Module errors — check the raw JSON file for detailed error messages in each section
