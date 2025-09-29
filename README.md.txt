# RECON

---

# Recon là gì

Recon là quá trình đi tìm các thông tin về scope nhằm tăng attack surface. 

Khi recon ta cần đặt ra 3 câu hỏi:

- WHAT: Tìm các thông tin gì?
- WHERE: Tìm các thông tin đó ở đâu?
- HOW: Tìm thông tin đó bằng cách nào?

---

# FLOW RECON đơn giản

![image.png](image.png)

# Recon SubDomain

> Mục đích của Recon subdomain là tìm ra các subdomain của domain chính.
> 

## Tool sử dụng

### Amass

> **Tool này sử dụng để enumeration các SubDomain của 1 trang web.**
> 

**Cách Amass hoạt động:**

Amass sẽ thu thập các thông tinh từ nhiều nguồn và tổng hợp lại. Amass thu thập các thông tin từ:

- API:
    
    ```jsx
    360PassiveDNS, Ahrefs, AnubisDB, BeVigil, BinaryEdge, BufferOver, BuiltWith, C99, Chaos, CIRCL,
    DNSDB, DNSRepo, Deepinfo, Detectify, FOFA, FullHunt, GitHub, GitLab, GrepApp, Greynoise,
    HackerTarget, Hunter, IntelX, LeakIX, Maltiverse, Mnemonic, Netlas, Pastebin, PassiveTotal,
    PentestTools, Pulsedive, Quake, SOCRadar, Searchcode, Shodan, Spamhaus, Sublist3rAPI,
    ThreatBook, ThreatMiner, URLScan, VirusTotal, Yandex, ZETAlytics, ZoomEye
    ```
    
- Certificate:
    
    ```jsx
    Active pulls (optional), Censys, CertCentral, CertSpotter, Crtsh, Digitorus, FacebookCT
    ```
    
- DNS:
    
    ```jsx
    Brute forcing, Reverse DNS sweeping, NSEC zone walking, Zone transfers, FQDN
    alterations/permutations, FQDN Similarity-based Guessing
    ```
    
- Routing:
    
    ```jsx
    ASNLookup, BGPTools, BGPView, BigDataCloud, IPdata, IPinfo, RADb, Robtex, ShadowServer,
    TeamCymru
    ```
    
- Scraping:
    
    ```jsx
    AbuseIPDB, Ask, Baidu, Bing, CSP Header, DNSDumpster, DNSHistory, DNSSpy, DuckDuckGo,
    Gists, Google, HackerOne, HyperStat, PKey, RapidDNS, Riddler, Searx, SiteDossier, Yahoo
    ```
    
- Web Archives:
    
    ```jsx
    Arquivo, CommonCrawl, HAW, PublicWWW, UKWebArchive, WaybackMachine
    ```
    
- WHOIS:
    
    ```jsx
    AlienVault, AskDNS, DNSlytics, ONYPHE, SecurityTrails, SpyOnWeb, WhoisXMLAPI
    ```
    

**Cách sử dụng:**

- amass viz
    
    > `amass viz` chuyển dữ liệu Amass (DB / JSON) thành các định dạng đồ thị/visualization để bạn phân tích mối quan hệ giữa domain ↔ subdomain ↔ IP ↔ ASN.
    > 
    
    ### Input (nguồn dữ liệu)
    
    - `dir <path>` — thư mục chứa **graph database** (Amass DB directory) → dùng khi bạn đã lưu DB bằng `amass db` / `amass enum -db`.
    - `i <file>` — file JSON operations/data xuất từ Amass (thay vì DB).
    - `d <domain>` / `df <file>` — chỉ chọn domain(s) để export từ DB/JSON.
    
    ### Output formats (mỗi format cho mục đích khác nhau)
    
    - `dot` — xuất **DOT** (Graphviz) `.dot` file. Dùng `dot` để render PNG/PDF.
    - `gexf` — xuất **GEXF** (Gephi) để mở bằng Gephi (graph analysis).
    - `d3` — xuất HTML dùng **D3 v4 force simulation** (interactive, mở trình duyệt).
    - `graphistry` — xuất JSON phù hợp cho Graphistry (visualization cloud/local).
    - `maltego` — xuất CSV cho Maltego (import vào Maltego transform/graph).
    - `o <dir>` hoặc `oA <prefix>` — nơi/tiền tố lưu file xuất.
- **amass enum:**
    
    **Input / domain & files**
    
    - `d <domain>`: chỉ định domain (có thể gọi nhiều lần).
    - `df <file>`: đọc nhiều domain từ file (mỗi dòng một domain).
    - `nf <file>`: file chứa subdomain đã biết (để tránh lặp).
    - `df` + `d` bạn dùng khi chạy cho nhiều target.
    
    **Chế độ hoạt động**
    
    - `passive`: chỉ dùng nguồn passive (không resolve DNS, ít gây traffic). Dùng để stealth.
    - `active`: bật một số hành vi active (AXFR, certificate grabs).
    - `brute`: bật brute-force (tạo candidate từ wordlist).
    - `norecursive` / `min-for-recursive`: điều khiển recursive brute; `noalts` / `alts` liên quan alter names.
    
    **Brute / alteration**
    
    - `w <wordlist>`: wordlist cho brute forcing.
    - `aw <wordlist>`: wordlist cho alterations (tạo biến thể).
    - `wm` / `awm`: hashcat-style masks cho brute/alter.
    - `max-depth`: giới hạn số labels (ví dụ bao nhiêu tầng sub.domain.com).
    
    **Output / logging**
    
    - `o <file>`: output text.
    - `json <file>`: output JSON chi tiết.
    - `oA <prefix>`: prefix cho tất cả output.
    - `dir <path>`: thư mục chứa output.
    - `log <file>`: nơi ghi lỗi.
    - `src`: in luôn nguồn phát hiện (rất hữu ích để đánh giá độ tin cậy).
    
    **DNS / Resolvers / Rate-limits**
    
    - `r <resolver>` / `rf <file>`: danh sách **untrusted** resolvers (các resolver ngoài; cẩn trọng).
    - `tr <resolver>` / `trf <file>`: **trusted** resolvers (dành cho resolvers bạn tin tưởng).
    - `dns-qps <int>`: tối đa query/sec tổng. (dùng để throttle)
    - `rqps`, `trqps`: QPS cho từng untrusted / trusted resolver.
    - `p <ports>`: ports để probe (mặc định 80,443).
    - `iface <if>`: gửi traffic qua interface cụ thể.
    
    **Scope mở rộng (IP/ASN/CIDR)**
    
    - `addr <ips/ranges>`: nhập IP/range để tìm host liên quan.
    - `cidr <cidrs>`: nhập CIDR(s) để include.
    - `asn <ASNs>`: include theo ASN.
    
    **Control / behavior**
    
    - `timeout <minutes>`: số phút chạy trước khi dừng.
    - `silent`: không in ra console.
    - `v`: verbose / debug.
    - `demo`: làm mờ sensitive output cho demo.
    - `bl <list>` / `blf <file>`: blacklist subdomain không khám phá.
    - `ef` / `if` / `include` / `exclude`: chọn/exclude data sources.
    
    **Deprecated / legacy**
    
    - `noalts`, `nolocaldb`, `max-dns-queries` — đã/deprecated (sẽ bị remove). Tránh dùng.
- **amass Intel**
    
    > `amass intel` thu thập **thông tin tình báo** (whois, ASN, netblocks, reverse lookups, certificate names...) để **mở rộng scope** trước khi chạy enumeration. Dùng khi bạn muốn biết IP/ASN/netblocks liên quan tới domain, hay tìm targets bổ sung.
    > 
    
    ### Input / domain / files
    
    - `d <domain>`: domain mục tiêu (có thể dùng nhiều lần).
    - `df <file>`: đọc danh sách domain từ file (mỗi dòng 1 domain).
    - `whois`: thực hiện **reverse whois** cho domain(s) — lấy các domain liên quan thông qua WHOIS info.
    
    ### Network / addressing (mở rộng scope)
    
    - `addr <ips,ranges>`: cung cấp IP hoặc range (vd `1.2.3.4,10.0.0.1-254`) để tìm host/nghiên cứu.
    - `cidr <cidrs>`: nhập CIDR(s) (vd `192.168.0.0/24`) để probe/lookup.
    - `asn <ASN>`: nhập ASN(s) để thu toàn bộ netblocks / host thuộc ASN đó.
    - `org <string>`: tìm AS whose description match string (tìm theo tên tổ chức).
    
    ### Active / certificate
    
    - `active`: thực hiện **certificate name grabs** (lấy tên từ certs) — hữu ích để tìm subdomain nằm trên certs.
        
        > Lưu ý: active có thể gửi request tới CT endpoints hoặc peers, tùy config.
        > 
    
    ### Resolvers / DNS control
    
    - `r <resolver>` / `rf <file>`: preferred DNS resolvers (dùng để tra cứu).
    - `max-dns-queries <int>`: maximum concurrent DNS queries (throttle).
    - `p <ports>`: ports để probe (mặc định `80,443`).
    
    ### Include / Exclude data sources
    
    - `if <file>`: file liệt kê sources **bao gồm**.
    - `ef <file>`: file liệt kê sources **loại trừ**.
    - `include <list>` / `exclude <list>`: tên nguồn để include/exclude (phân cách bằng dấu phẩy).
    
    ### Output / logging / behavior
    
    - `o <file>`: path file text output.
    - `dir <path>`: folder chứa output files.
    - `log <file>`: file ghi lỗi/log.
    - `json` không có trong intel (enum có) — intel thường xuất txt.
    - `src`: in **nguồn** phát hiện (rất hữu ích để đánh giá độ tin cậy).
    - `ip`, `ipv4`, `ipv6`: show IPs for discovered names.
    - `timeout <minutes>`: thời lượng chạy trước khi dừng.
    - `v`: verbose (debug/troubleshoot).
    - `demo`: mask sensitive output cho demo.
- **amass track**
    
    > `amass track` so sánh các lần enumerate đã lưu trong **Amass DB** và báo:
    > 
    - host **mới** xuất hiện kể từ lần trước,
    - host **bị mất** (không còn),
    - hoặc thay đổi metadata giữa hai lần.
        
        Dùng để phát hiện subdomain mới (alerting) hoặc regressions.
        
        - `d <domain>`
            
            Domain mục tiêu (có thể chỉ một hoặc nhiều domain, phân tách bằng dấu phẩy).
            
        - `df <file>`
            
            File list domain (mỗi dòng 1 domain).
            
        - `dir <path>`
            
            Thư mục chứa **graph database** (amass DB directory). Nếu không chỉ, mặc định là `~/.config/amass` hay nơi bạn đã lưu DB.
            
        - `history`
            
            Hiển thị sự khác nhau giữa **tất cả** các cặp enumerate (tạo báo cáo lịch sử chi tiết). Dùng khi muốn xem thay đổi toàn bộ lịch sử.
            
        - `last <int>`
            
            Chỉ so sánh `n` lần enumerate gần nhất (ví dụ `-last 2` sẽ so sánh 2 lần gần nhất).
            
        - `since <timestamp>`
            
            Loại trừ các enumerate **trước** thời điểm chỉ định. Timestamp format:
            
            ```
            01/02 15:04:05 2006 MST
            ```
            
            (ví dụ: `09/29 09:00:00 2025 +0700` hoặc `09/01 00:00:00 2025 +0700` — theo format Go time).
            
            Dùng để chỉ track thay đổi từ ngày/thời gian bạn muốn.
            
        - `config <file>`
            
            Path tới file config (nếu cần override).
            
        - `silent` / `nocolor`
            
            Tắt output / colorize.
            
- **amass db:**
    
    > `amass db` là công cụ thao tác/tra cứu **graph database** của Amass (nơi lưu nodes/edges: domain ↔ ip ↔ asn ↔ nguồn...). Dùng để:
    > 
    > - khởi tạo/điều hướng thư mục DB,
    > - liệt kê các lần enumerate đã lưu,
    > - in / xuất tên vừa phát hiện,
    > - xem IP/ASN summary,
    > - xuất JSON để downstream processing.
    
    **Input / target**
    
    - `d <domain>`: domain(s) để lọc/nghị vấn.
    - `df <file>`: nhiều domain từ file (mỗi dòng 1 domain).
    
    **DB location / init / listing**
    
    - `dir <path>`: thư mục chứa graph DB (ví dụ `./amass_db`).
    - `list`: in danh sách các enumerate (có số thứ tự) cho domain được lọc.
    
    **Hiển thị / xuất**
    
    - `show`: in kết quả cho enumerate index + domain (phải kết hợp `enum`).
    - `names`: chỉ in **tên (subdomain)** đã phát hiện (danh sách thuần).
    - `json <file>`: xuất JSON (thích hợp cho pipeline).
    - `o <file>`: xuất stdout/stderr vào text file.
    - `src`: in **nguồn** phát hiện mỗi tên (giúp đánh giá độ tin cậy).
    
    **Thông tin địa chỉ**
    
    - `ip`, `ipv4`, `ipv6`: show địa chỉ IP tương ứng cho tên được liệt kê.
    
    **Summary / utility**
    
    - `summary`: in bảng tóm tắt ASN (mấy IP thuộc ASN nào...).
    - `enum <int>`: chỉ số enumerate (index) dùng với `show` hoặc `json` (index lấy từ `list`).
    
    **Behaviour**
    
    - `silent`, `nocolor`, `demo`, `v` etc. (logging/display control)