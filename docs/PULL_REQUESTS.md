# Pull Requests — Tyler code

Stacked PR order (base → tip):

1. **main** → `tyler/web-pcap-upload` — Web PCAP upload (auto-scan after upload)
2. **tyler/web-pcap-upload** → `tyler/pcap-compare` — Compare two PCAP files
3. **tyler/pcap-compare** → `tyler/ioc-extraction` — IOC extraction per file
4. **tyler/ioc-extraction** → `tyler/search-toolbar-layout` — Search toolbar layout fix

Integration branch: `tyler/develop` (all features + other improvements).

## Push and open PRs

```bash
git remote add origin <your-github-repo-url>
git push -u origin main
git push -u origin tyler/web-pcap-upload
git push -u origin tyler/pcap-compare
git push -u origin tyler/ioc-extraction
git push -u origin tyler/search-toolbar-layout
git push -u origin tyler/develop
```

### PR 1: Web PCAP upload

**Title:** feat: web PCAP upload with auto-scan after upload

**Summary:**
- `POST /pcaps/upload` saves file under uploads folder and runs `scan_single_file`
- Drag-and-drop upload zone and Upload button in the search UI
- Progress bar and toast on success (includes alert count when triggered)

**Test plan:**
- Upload a small `.pcapng` via UI
- Confirm file appears in table after refresh
- Upload duplicate name → suffix applied
- Upload >200MB → 413 error

---

### PR 2: Two-file PCAP comparison

**Title:** feat: compare two indexed PCAP files

**Summary:**
- `GET /pcaps/compare?hash_a=&hash_b=` returns protocol overlap, similarity %, size/packet diff
- Select two files via checkboxes, open Compare modal

**Test plan:**
- Select 2 files with overlapping protocols → similarity shown
- Select same file twice → blocked in UI
- Compare files with disjoint protocols → low similarity

---

### PR 3: IOC extraction per file

**Title:** feat: IOC extraction (IP, port, domain) per PCAP

**Summary:**
- `GET /pcaps/{hash}/ioc` via tshark field extraction
- Analysis modal IOC tab + Info modal **IOC / Timeline** button

**Test plan:**
- Open IOC tab on HTTP capture → IPs/domains listed
- Timeline tab shows time buckets

---

### PR 4: Search toolbar layout fix

**Title:** fix: split search toolbar into search row and action row

**Summary:**
- Search input + Search button on first row
- Scan, Dashboard, Config, feature buttons on second row (no overflow on narrow screens)

**Test plan:**
- Resize browser → buttons remain usable
- All toolbar actions still work
