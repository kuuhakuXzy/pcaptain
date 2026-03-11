1. The landing page is a bit empty when the project opens up.  Consider either placing a few of the more interesting graphs on the frontpage to greet the user, or perhaps showing a list of randomly pcaps just to get the user started

### Improve Landing Page Content

The landing page appeared somewhat empty when the project first loads.  
To improve the user experience, additional information and useful system details were added.

- **Added PCAPTAIN tool information to the landing page**
  - How PCAPTAIN Works (updated in `/frontend/components/search` files)
  - Supported file extensions (updated in `/frontend/components/search` files)
  - Scan options (updated in `/frontend/components/search` files)

- **Display total PCAP files in the system**
  - Implemented `count_pcaps` function in `/backend/routes/pcaps.py`, cmd: "curl http://localhost:7000/pcaps/count"
  - Added backend API to return the total number of PCAP files
  - Connected frontend to the API
  - Displayed the file count on the landing page

- **Display current scan mode**
  - Added frontend function `loadScanMode()` to retrieve scan mode from backend configuration
  - Called `/config` API to get the current `pcap.scan_mode`
  - Displayed the scan mode dynamically on the landing page

2. Currently, the backend will skip Invalid or Broken files, but it could be valuable information to know why these files are skipped.  Is it because a packet is cut short, or it is an incorrect file type, or perhaps it is the result of processing crashing.  A separate list containing a path to these pcaps and the processing problems would be helpful

### Track Processing Errors for Skipped PCAP Files

Previously, the backend would silently skip invalid or broken PCAP files during scanning.  
To improve debugging and monitoring, a mechanism was added to track the reasons why files are skipped.

- **Added error tracking structure**
  - Introduced `processing_errors: List[Dict[str, str]]` in `/backend/services/config.py`
  - Stores skipped PCAP file paths and corresponding failure reasons

- **Enhanced scan logic**
  - Updated `/backend/services/scan.py` to capture processing issues during file scanning
  - Logged and stored reasons for skipped files

- **Common tracked reasons**
  - `EXCLUDED_OR_INVALID_EXTENSION` – file extension not in allowed list
  - `INVALID_PCAP_OR_BROKEN_FILE` – PCAP contains zero readable packets
  - `NO_PROTOCOLS_FOUND` – scan completed but no protocols detected
  - `FASTSCAN_LIMITATION` – protocol not detected due to FAST scan limits
  - `PROCESSING_ERROR` – unexpected processing failure

- **Logging**
  - All skipped files and reasons are stored in `config.pcap.processing_errors`
  - Summary of processing errors is logged for monitoring and troubleshooting


3. Pie charts would be could valuable to be sorted by name, rather than by value.  Basically, any other UI/UX updates that come to your mind in the graphs section to make things more clear

### Improve Graph UI/UX and Pie Chart Readability

To make the graphs section clearer and easier to interpret, several UI/UX improvements were implemented.

- **Sort pie chart data by name**
  - Updated pie chart generation to sort protocol categories alphabetically instead of by value

- **Custom legend display**
  - Implemented a custom legend list
  - Each entry displays:
    - protocol category
    - number of files
    - percentage of total files

- **Improved tooltip information**
  - Added custom tooltip to show both file count and percentage

- **Improved labeling**
  - Enhanced graph labels and section titles for better readability
  - Added clearer overview label: `Total valid PCAP Files For The Current Scanning`

