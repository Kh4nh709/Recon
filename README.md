# RECON

# 1_Technology fingerprinting

## Tool

- Wappalyzer CLI
- Wappalyzer extension

## Result:

```
URL: https://www.hertz.com
Miscellaneous: Webpack
Widgets: Twitter
Analytics: Dynatrace ; Google Analytics
Comment systems: Livefyre
Security: Securiti ; reCAPTCHA ; Imperva ; HSTS
Font scripts: Google Font API
CDN: Imperva
Advertising: Twitter Ads ; Google Publisher Tag ; DoubleClick for Publishers (DFP)
Tag managers: Google Tag Manager
JavaScript libraries: 
	Underscore.js ; 
	Modernizr [2.8.3] None CVE 
	Lodash ;
	jQuery Migrate [3.1.0] : None CVE 
	jQuery [3.4.1] : CVE-2020-11022, CVE-2020-11023
	core-js [2.6.12] : none cve
RUM: Dynatrace RUM
JavaScript frameworks: 
	RequireJS [2.1.16] : CVE-2024-38998 REJECTED
	Backbone.js [0.9.2] : NONE CVE
Web servers: Nginx
Payment processors: Stripe
Web server extensions: Nginx
Maps: Leaflet
Programming languages: Java

```
![image.png](https://github.com/Kh4nh709/Recon/blob/main/image.png)

![image.png](image%201.png)

# 2_Dorking

## Information

- Tech vulnerability
    - Version
    - Error message
    - Directory listing
- **Sensitive information**
    - File config
    - File backup
- Door
    - Hidden login
    - API và Enpoint

## Tool

- google dorking
- Github dorking

# 3_Template base scanning

## Tool:

nuclei scan template

## Result:

```
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.10

		projectdiscovery.io

[WRN] Found 1 templates with syntax error (use -validate flag for further examination)
[WRN] Found 2 templates with runtime error (use -validate flag for further examination)
[INF] Current nuclei version: v3.4.10 (latest)
[INF] Current nuclei-templates version: v10.2.9 (latest)
[INF] New templates added in latest release: 182
[INF] Templates loaded for current scan: 8497
[INF] Executing 8295 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 202 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Running httpx on input host
[INF] Found 1 URL from httpx
[INF] Templates clustered: 1796 (Reduced 1685 Requests)
[INF] Using Interactsh Server: oast.me

[azure-domain-tenant] [http] [info] https://login.microsoftonline.com:443/hertz.com/v2.0/.well-known/openid-configuration ["c99aab19-376d-49c5-8e93-00f03b99b5eb"]
[external-service-interaction] [http] [info] https://hertz.com
[external-service-interaction] [http] [info] https://hertz.com
[missing-sri] [http] [info] https://www.hertz.com/rentacar/reservation/ ["https://cdn-prod.eu.securiti.ai/consent/auto_blocking/c3001264-2465-4c40-a23d-05543a15c547/d9c7d7c5-9492-4062-bc49-6c2120bcf117.js","https://cdn-prod.eu.securiti.ai/consent/sdk-stub.js","https://api.mqcdn.com/sdk/mapquest-js/v1.3.2/mapquest.js","https://www.google.com/recaptcha/enterprise.js","https://js.stripe.com/v3/","https://api.mqcdn.com/sdk/mapquest-js/v1.3.2/mapquest.css"]
[request-based-interaction:dns] [http] [info] https://hertz.com/
[request-based-interaction:dns] [http] [info] https://hertz.com/
[request-based-interaction:dns] [http] [info] https://hertz.com/
[request-based-interaction:dns] [http] [info] https://hertz.com/
[tls-version] [ssl] [info] hertz.com:443 ["tls12"]
[tls-version] [ssl] [info] hertz.com:443 ["tls13"]
[rdap-whois:registrationDate] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["1996-07-02T04:00:00Z"]
[rdap-whois:lastChangeDate] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["2025-06-11T23:00:04Z"]
[rdap-whois:expirationDate] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["2026-07-01T04:00:00Z"]
[rdap-whois:nameServers] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["NS11.HERTZ.COM","NS12.HERTZ.COM","NS13.HERTZ.COM","NS10.HERTZ.COM"]
[rdap-whois:secureDNS] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["true"]
[rdap-whois:status] [http] [info] https://rdap.verisign.com/com/v1/domain/hertz.com ["client delete prohibited","client transfer prohibited","client update prohibited","server delete prohibited","server transfer prohibited","server update prohibited"]
[dmarc-detect] [dns] [info] _dmarc.hertz.com [""v=DMARC1; p=quarantine; fo=1; rua=mailto:dmarc_rua@emaildefense.proofpoint.com,mailto:dmarc_rua@hertz.com; ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com,mailto:dmarc_ruf@hertz.com""]
[mx-fingerprint] [dns] [info] hertz.com ["10 mxa-00034201.gslb.pphosted.com.","10 mxb-00034201.gslb.pphosted.com."]
[dnssec-detection] [dns] [info] hertz.com
[spf-record-detect] [dns] [info] hertz.com ["v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all""]
[txt-fingerprint] [dns] [info] hertz.com [""_globalsign-domain-verification=-jzefWdoUCJxai9FWTvTDdRNc9N2JJFgFuKXH3uf7r"",""msfpkey=3bh3x8yaiq2v4u7299q3pav40"",""ff965r3f3xkp2dmt55k49yhvx2ssydw6"",""amazonses:/IPm1hhpAyQ6uAN3f5XmTLtE6VZpUY582Ppr6IOcIVU="",""infoblox-domain-mastery=7ada838ff03c6654eac9005e99b87df0bd7804a0345fa5e54ca2d91c5db9ee287e"",""google-site-verification=wyQk_1YHMYyIMjnMnFHe9mV1rFZov5GexcMMgoyz6e4"",""parkable-domain-verification=ioyWPZCFOHUtBmZ_91fSt7_cqzkzGzQWnH1sEFD_Mow="",""MS=ms13411640"",""v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all"",""atlassian-domain-verification=UIjQlEnCPaW6i0RzVM3AR436tSaICZapas/EUtMfpkfZBIa0JMzmiltvbLYSbZug"",""spf2.0/pra ip4:66.216.133.19 ip4:66.109.239.154 ip4:66.109.242.2 ?all""]
[caa-fingerprint] [dns] [info] hertz.com
[nameserver-fingerprint] [dns] [info] hertz.com ["ns12.hertz.com.","ns13.hertz.com.","ns10.hertz.com.","ns11.hertz.com."]
[ssl-issuer] [ssl] [info] hertz.com:443 ["GlobalSign nv-sa"]
[ssl-dns-names] [ssl] [info] hertz.com:443 ["hertz-saudi.com","*.dollarcarrental.co.nz","hertzondemand.com","hertz.ie","www.hertz.co.th","*.hertz.be","*.hertz.com.pt","*.hertz.se","hertz.be","*.hertz.co.uk","hertz.se","www.hertz.com.bh","www.hertz.com.au","www.hertz.jo","*.hertz.it","hertz.co.uk","hertzbilling.com","hertz.co.nz","stage.hts.hertz.com","*.c2c-qa.hertz.com","www.hertz-autovermietung.com.pl","apipreprod.hertz.com","www.hertz.ee","*.digital.nz.dtgthrifty.io","rates-perf.hertz.com","nl.hertz.be","www.hertz.co.nz","www.hertz247.cz","hertz.de","*.hertz.ch","www.hertz.co.ao","www5.hertz.com","*.digital.au.dtgdollar.io","hertz.no","*.hertz.fr","es.hertz.com","hertz.qa","www.hertz-kuwait.com","*.hertz.com","*.c2c-prod.hertz.com","hertz.ee","*.connectbyhertz.es","hertz.com.sg","www.hertzdatalink.com","www.hertzautovermietung.pl","hertz247.cz","www.hertzondemand.com","*.hertz.com.mt","www.hertz.lt","*.hertz.co.kr","dollar.com","*.fireflycarrental.com","hertz.com","hertz.co.th","connectbyhertz.co.uk","hertz.at","www.hertzcaribbean.com","*.hertz.cn","hertz.pl","hertz.com.mt","unsubscribe.hertz.com","email.hertz.com","hertz.cn","*.hertz.es","hertz.bh","hertz-kuwait.com","*.hertz-europe.com","hertz-japan.com","connectbyhertz.com","hertz.nl","hertz.es","mstaging.thrifty.com","fireflycarrental.com","imperva.com","hertz.co.ao","connectbyhertz.es","hertz.cv","www.connectbyhertz.com","hertzcaribbean.com","hertz.ch","*.hertz.fi","*.hertz.nl","www.hertz.com.hk","*.hertz.ae","staging.thrifty.com","*.connectbyhertz.co.uk","www.hertz.qa","images2.hertz.com","japan.hertz.com","*.digital.au.dtgthrifty.io","*.hertz.at","sa.hertz.com","hertzautovermietung.pl","www.hertzautovermietung.com.pl","hertz.com.hk","hertzvans.co.uk","www.hertz.cz","hertz.si","hertz.pt","hertz.com.tw","stage-rss.hertz.com","hertzdk.dk","www.hertz-autovermietung.pl","hertz.hu","hertz.co.kr","hertz.com.au","hertz.ru","hertz.com.bh","hertz.lt","*.hertz.ca","www.hertz.hu","*.hertz.pt","staging.dollar.com","wwwpreprod.hertz.com","mstaging.dollar.com","www.hertz-japan.com","*.hertz.ie","www.hertz.cv","hertzautovermietung.com.pl","hertz-autovermietung.pl","hertz.fr","www.hertz-saudi.com","hertz.ae","hertz.it","www.hertz.com.tw","*.c2c-preprod.hertz.com","www.hertz.bh","www.hertz.pl","hertz.fi","www.hertzdk.dk","hts.hertz.com","dollarcarrental.co.nz","hertz-autovermietung.com.pl","hertz.jo","*.hertzvans.co.uk","hertz-europe.com","hertz.com.pl","www.hertz.com.kw","*.c2c-dev.hertz.com","*.dollar.com","www.hertz.si","*.thrifty.com","hertz.com.pt","touchless-stage.hertz.com","hertz.com.kw","www.hertz.com.pl","hertz.cz","hertz.ca","thrifty.com","*.hertz.ru","hertzdatalink.com","www.hertz.co.id","*.hertz.no","hertz.co.id","*.hertz.com.sg","*.hertz.de","www.hertzbilling.com"]
[wildcard-tls] [ssl] [info] hertz.com:443 ["CN: imperva.com","SAN: [*.fireflycarrental.com www.hertz.com.hk hertz.pt www.hertz-kuwait.com www.hertz.com.pl *.hertz.com hertz.com.tw *.dollar.com *.hertz.ae dollar.com hertzautovermietung.com.pl connectbyhertz.com hertz-europe.com *.hertz.ie nl.hertz.be staging.thrifty.com www.hertzbilling.com hertz.pl www.hertz.co.th *.hertz.at hertz-autovermietung.pl *.c2c-prod.hertz.com www.hertz.pl www.hertzcaribbean.com *.digital.au.dtgdollar.io *.hertz.it www.hertzdatalink.com fireflycarrental.com hertz.com.mt *.hertz.be *.hertz.ru www.hertz.hu www.hertzautovermietung.pl *.connectbyhertz.co.uk *.hertz.com.pt www.hertz.qa apipreprod.hertz.com hertz.nl hertz.co.uk hertz.fi hertz.no *.hertz.fr www.hertz.co.nz hertz.fr *.hertz-europe.com www.hertz.ee hertz.es images2.hertz.com www.hertz247.cz hertzbilling.com imperva.com sa.hertz.com hertz-saudi.com japan.hertz.com hertz.ee hertzautovermietung.pl *.hertz.pt hertz.com.pl www.hertzdk.dk unsubscribe.hertz.com *.digital.au.dtgthrifty.io hertz.co.nz stage-rss.hertz.com www.connectbyhertz.com hertzdatalink.com *.connectbyhertz.es hertzdk.dk www.hertz.com.tw email.hertz.com www.hertz.si hertz.de hertzcaribbean.com www.hertzautovermietung.com.pl hertz.com *.dollarcarrental.co.nz hertz.lt hertz.com.hk *.thrifty.com hertz.com.pt hertz247.cz connectbyhertz.es hertz.cv hertz.co.kr hertz.cz stage.hts.hertz.com www.hertz.cv www.hertzondemand.com www.hertz.com.kw *.c2c-preprod.hertz.com *.hertz.com.mt touchless-stage.hertz.com www.hertz.co.id hertzvans.co.uk staging.dollar.com hertz.co.th hertz.ca www.hertz.cz hertz.ch www.hertz-autovermietung.pl www.hertz-saudi.com hertz.cn wwwpreprod.hertz.com *.hertz.es *.hertz.fi *.hertz.no hts.hertz.com hertz.se www.hertz.lt dollarcarrental.co.nz hertz.si hertz-autovermietung.com.pl hertz.com.au *.hertz.co.kr *.hertz.nl es.hertz.com hertzondemand.com mstaging.dollar.com *.hertz.se hertz.be hertz.ru www.hertz.com.bh *.digital.nz.dtgthrifty.io hertz-japan.com hertz.jo thrifty.com hertz.bh hertz.co.id rates-perf.hertz.com connectbyhertz.co.uk www.hertz-japan.com hertz.com.bh www.hertz.com.au hertz.at *.hertz.ch *.hertzvans.co.uk hertz.co.ao hertz.com.sg *.c2c-qa.hertz.com *.hertz.ca *.c2c-dev.hertz.com hertz.com.kw hertz.ae *.hertz.cn www.hertz-autovermietung.com.pl www.hertz.co.ao www.hertz.jo hertz.it *.hertz.co.uk *.hertz.com.sg hertz.qa hertz.hu mstaging.thrifty.com *.hertz.de www.hertz.bh www5.hertz.com hertz-kuwait.com hertz.ie]"]
[INF] Scan completed in 11m. 26 matches found.

```

### Phân tích cơ bản:

1. **Missing SRI** trên external scripts - Risk: Supply chain attacks
2. **4 DNS interactions** - Có thể là false positives từ Nuclei
3. **202 unsigned templates** - Cần validate các template không ký

# 4_Directory enumeration

## Tool:

- Dirsearch
- FFUF

## Result:

```
302     0B   https://www.hertz.com/shop    -> REDIRECTS TO: https://www.hertzcarsales.com/?utm_campaign=In-Location&utm_id=In-Location&utm_medium=Rtl-Jacket&utm_source=POS
302   109B   https://www.hertz.com/login    -> REDIRECTS TO: https://www.hertz.com/rentacar/member/login?iss=https%3A%2F%2Fhertz-dev.us.auth0.com%2F
302   109B   https://www.hertz.com/Login    -> REDIRECTS TO: https://www.hertz.com/rentacar/member/login?iss=https%3A%2F%2Fhertz-dev.us.auth0.com%2F
302     0B   https://www.hertz.com/terms    -> REDIRECTS TO: https://hertz.ltschat.com/terms-conditions/
302     0B   https://www.hertz.com/Shop    -> REDIRECTS TO: https://www.hertzcarsales.com/?utm_campaign=In-Location&utm_id=In-Location&utm_medium=Rtl-Jacket&utm_source=POS
302     0B   https://www.hertz.com/enroll    -> REDIRECTS TO: https://www.hertz.com/us/en/enrollment
302     0B   https://www.hertz.com/Terms    -> REDIRECTS TO: https://hertz.ltschat.com/terms-conditions/
302    11KB  https://www.hertz.com/tmobile    -> REDIRECTS TO: https://www.hertz.com/rentacar/rental-car-deals/tmobile-offer
302   109B   https://www.hertz.com/LOGIN    -> REDIRECTS TO: https://www.hertz.com/rentacar/member/login?iss=https%3A%2F%2Fhertz-dev.us.auth0.com%2F
302     0B   https://www.hertz.com/booknow    -> REDIRECTS TO: https://www.hertz.com/us/en/deals-and-offers/save-up-on-your-next-road-trip?
```

# 5_Wayback history

## Tool:

- Gau: quét full URL từ wayback history, crawl, AlienVault,…
- uro: lọc URL trung lặp
- httpx: kiểm tra xem url có hoạt động

## Result

### gau:

```
https://www.hertz.com --threads 20 --from 202201 > result_recon/5_Wayback_History/gau.txt
```

[https://drive.google.com/file/d/1iZTMpnN1toW0jzY_MRHrlKwur-8xU-cY/view?usp=drive_link](https://drive.google.com/file/d/1iZTMpnN1toW0jzY_MRHrlKwur-8xU-cY/view?usp=drive_link)

### uro:

```
cat result_recon/5_Wayback_History/gau.txt | uro -f hasext | grep -iE "\.js($|[?/#;])" > result_recon/5_Wayback_History/uro_extension_js.txt

```

[https://drive.google.com/file/d/13QwWSaH4KlVogGWBNYkOK0VW9FS8-Swd/view?usp=drive_link](https://drive.google.com/file/d/13QwWSaH4KlVogGWBNYkOK0VW9FS8-Swd/view?usp=drive_link)

### httpx:

```
cat result_uro.txt | httpx -mc 200 -title > result_httpx.txt
```

[https://drive.google.com/file/d/1bJa2C6GFVDXVlYhYVa1RNfmr8ajP_cRs/view?usp=drive_link](https://drive.google.com/file/d/1bJa2C6GFVDXVlYhYVa1RNfmr8ajP_cRs/view?usp=drive_link)

```
#gau
gau https://www.hertz.com --threads 20 --from 202201 > result_recon/5_Wayback_History/gau.txt
#uro
cat result_recon/5_Wayback_History/gau.txt | uro -f hasparams > result_recon/5_Wayback_History/uro_parameter.txt
cat result_recon/5_Wayback_History/gau.txt | uro -f noparams > result_recon/5_Wayback_History/uro_url.txt
cat result_recon/5_Wayback_History/gau.txt | uro -f hasext > result_recon/5_Wayback_History/uro_extension.txt
cat result_recon/5_Wayback_History/gau.txt | uro -f hasext | grep -iE "\.js($|[?/#;])" > result_recon/5_Wayback_History/uro_extension_js.txt
#httpx
httpx -l result_recon/5_Wayback_History/uro_url.txt -silent -o result_recon/5_Wayback_History/httpx.txt
httpx -l result_recon/5_Wayback_History/uro_extension_js.txt -silent -o result_recon/5_Wayback_History/httpx_js.txt
httpx -l result_recon/5_Wayback_History/uro_parameter.txt -silent -o result_recon/5_Wayback_History/httpx_parameter.txt

```

# 6_Crawler

## Tool

- Katana

```
katana -u https://www.hertz.com/  d 5 -jc -o result_crawler.txt
```

### Result:

[https://drive.google.com/file/d/1SqaiW0khVTzO388f-ES7h74dieGLx33F/view?usp=sharing](https://drive.google.com/file/d/1SqaiW0khVTzO388f-ES7h74dieGLx33F/view?usp=sharing)

### Result katana clear:

```
https://www.hertz.com/rentacar/navigation/templates/legalView.jsp
https://www.hertz.com/rentacar/navigation/templates/privacyPolicyView.jsp
https://www.hertz.com/rentacar/misc/index.jsp?targetPage=gold_FFP_TG.jsp
https://www.hertz.com/rentacar/misc/index.jsp?targetPage=usaa.jsp
https://www.hertz.com/rentacar/misc/index.jsp?targetPage=50-Plus-Car-Rental-Deals.jsp
https://www.hertz.com/rentacar/member/login
https://www.hertz.com/rentacar/member/enrollment/skinnyGold/fast
https://www.hertz.com/rentacar/partner/index.jsp?targetPage=ftRetroFormView.jsp
https://www.hertz.com/rentacar/reservation
https://www.hertz.com/rentacar/error/index.jsp
https://www.hertz.com/rentacar/misc/?targetPage=GPR_FAQs.jsp
https://www.hertz.com/rentacar/member/login/overlay
https://www.hertz.com/rentacar/emember/login/index.jsp?targetPage=loginView.jsp
https://www.hertz.com/rentacar/vehicleguide/index.jsp?targetPage=vehicleGuideHomeView.jsp
https://www.hertz.com/rentacar/hertzlink/index.jsp?targetPage=MasterCard_Premium.xml
https://www.hertz.com/rentacar/hertzlink/index.jsp?PID=7304739
https://www.hertz.com/rentacar/privacypolicy/index.jsp
https://www.hertz.com/rentacar/partner/index.jsp
https://www.hertz.com/rentacar/b2b/index.jsp?targetPage=diversityOverview.jsp
https://www.hertz.com/rentacar/member/login?iss=https://auth.hertz.com/
https://www.hertz.com/auth0-callback.model.json
https://offer.hertz.com/offers/index.jsp?targetPage=hbr-online-credit.jsp
https://offer.hertz.com/offers/assets/1758906708272/integrated/offer.js
https://dvir.hertz.com/api/health-check
https://dvir.hertz.com/damage-selfservice/create
https://dvir.hertz.com/damage-selfservice/login
https://dvir.hertz.com/damage-selfservice/customerLogin
https://dvir.hertz.com/damage-selfservice/link
https://dvir.hertz.com/damage-selfservice/success
https://extensions.hertz.com/index.html
https://ir.hertz.com/overview/default.aspx
https://ir.hertz.com/financials/sec-filings/default.aspx
https://ir.hertz.com/financials/quarterly-results/default.aspx
https://ir.hertz.com/governance/board-of-directors/default.aspx
https://ir.hertz.com/governance/committee-composition/default.aspx
https://ir.hertz.com/governance/governance-documents/default.aspx
https://ir.hertz.com/governance/leadership-team/default.aspx
https://ir.hertz.com/stock-info/default.aspx
https://ir.hertz.com/resources/investor-email-alerts/default.aspx
https://ir.hertz.com/search-results/default.aspx
https://ir.hertz.com/site-map/default.aspx
https://newsroom.hertz.com/wp-json/wp/v2/pages/8079
https://newsroom.hertz.com/wp-json/oembed/1.0/embed
https://www.hertz.com/us/en/blog
https://www.hertz.com/us/en/deals-and-offers
https://www.hertz.com/us/en/checkin
https://www.hertz.com/us/en/reservation/lookup
https://www.hertz.com/us/en/programs/business-rewards
https://www.hertz.com/us/en/programs/rideshare-rentals/uber-drivers
https://www.hertz.com/us/en/products-and-services/value-added-services/united-states

```

# 7_JS recon

## Tool:

- link finder
- secret finder
- nuclei js analysis

### Result

![image.png](image%202.png)

nuclie js analysis:

```

```

# 8_Parameter discovery

## tool:

- Arjun

## Result:

```
[*] Scanning 1/51: https://www.hertz.com/rentacar/navigation/templates/legalView.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, language, privacy, id, contact, pos

[*] Scanning 2/51: https://www.hertz.com/rentacar/navigation/templates/privacyPolicyView.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, language, privacy, pos, contact, id

[*] Scanning 3/51: https://www.hertz.com/rentacar/misc/index.jsp?targetPage=gold_FFP_TG.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, id, preview

[*] Scanning 4/51: https://www.hertz.com/rentacar/misc/index.jsp?targetPage=usaa.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, id, preview

[*] Scanning 5/51: https://www.hertz.com/rentacar/misc/index.jsp?targetPage=50-Plus-Car-Rental-Deals.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, preview, id

[*] Scanning 6/51: https://www.hertz.com/rentacar/member/login
[*] Probing the target for stability
[+] Heuristic scanner found 53 parameters: displayText, loginForgotPassword, cookieMemberOnLogin, homePageloginId, parentContext, url, pos, imageUrl, contactOption, cookieMemberOnLoginInPage, nvpLanguageSelected, rootContext, returnURL, memberLogout, topNavChange, logoUrl, value, h1, rightnowOverlayTitle, secDataID, topNavSubmit, loginId, topNavContactUs, loginCreateUserID, ca, wlClientId, founder, topNavCareer, telephone, result, homePagePassword, searchValue, changePosLang, contactType, password, language, logo, headerImage, topNavCountry, pageName, memberLogin, foundingDate, imageName, loginForgotPasswordNav, carrentaltext, returnTo, wlAudience, name, phone, searchButton, requestURL, webContext, tickerSymbol
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 7/51: https://www.hertz.com/rentacar/member/enrollment/skinnyGold/fast
[*] Probing the target for stability
[+] Heuristic scanner found 107 parameters: pos, rootContext, region, memberLogout, mobilePhoneActiveCountry, personalAddress1, currency, loginCreateUserID, creditCardNumber, dateModified, isRestrictEditPrivacyElection, mobilePhonePrefix, datePublished, passportIssueYear, passportIssueMonth, foundingDate, loginForgotPasswordNav, sendOffersByMail, passportId, passportExpiryYear, height, name, phone, webContext, homePageloginId, url, nvpLanguageSelected, returnURL, topNavChange, businessAddress2, topNavSubmit, loginId, lastName, passportExpiryDay, topNavCareer, telephone, searchValue, mobileNumber, changePosLang, password, contactType, width, logo, headerImage, email, topNavCountry, personalAddress2, emailVerify, cvvNumber, memberTier, skinnyPassword, tickerSymbol, displayText, loginForgotPassword, passwordVerify, businessAddress1, firstName, businessZipCode, description, personalCity, disclosePersonalInformation, passportExpDate, passportIssueDay, value, deSkgCdpNumber, dialect, rightnowOverlayTitle, secDataID, sg3dsTcConfirmation, founder, countryCode, result, homePagePassword, pageName, isFamilyFriendly, passportExpiryMonth, imageName, returnTo, businessName, passportCountry, addressType, searchButton, requestURL, sendOffersByEmail, homeAddressSelected, personalZipCode, cookieMemberOnLogin, parentContext, contactOption, imageUrl, skgEnrollmentIndicator, href, driversLicense, logoUrl, h1, topNavContactUs, memberType, wlClientId, businessCity, language, passportIssueDate, memberLogin, carrentaltext, dateCreated, wlAudience, headline, sgTcConfirmation
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 8/51: https://www.hertz.com/rentacar/partner/index.jsp?targetPage=ftRetroFormView.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 52 parameters: displayText, loginForgotPassword, cookieMemberOnLogin, homePageloginId, parentContext, url, pos, imageUrl, contactOption, nvpLanguageSelected, rootContext, returnURL, memberLogout, topNavChange, logoUrl, value, h1, rightnowOverlayTitle, secDataID, topNavSubmit, loginId, partnerTitle, topNavContactUs, loginCreateUserID, wlClientId, founder, topNavCareer, telephone, result, homePagePassword, searchValue, changePosLang, contactType, password, language, logo, headerImage, topNavCountry, pageName, memberLogin, foundingDate, imageName, loginForgotPasswordNav, carrentaltext, returnTo, wlAudience, name, phone, searchButton, requestURL, webContext, tickerSymbol
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 9/51: https://www.hertz.com/rentacar/reservation
[*] Probing the target for stability
[+] Heuristic scanner found 353 parameters: selectAnotherCountry, pos, referrerUrl, inpDropoffSearchType, rootContext, changeReturnLocation, companyId, shortFormNov, redeemPoints, memberLogout, returnDate, cannotReturn, clearAll, checkDiscount, alternativeCDPmessage, discounts, selectDropoffLocation, haveDiscount, addDiscountCodeInfoImgAlt, shortFormSep, pcNumber, rentalCarType, bannerAdsTitle, rateCode, orSimilar, selectCountry, confNmber, arrivingInfoRadioButton, dropoffDay, url, shortFormJul, typeInRateQuote, continueBooking, returnURL, topNavChange, appName, rentingCityCode, notArrivingAirlineTrain, calMonthMar, loginId, cdpBusinessTrip, Other, corporateRate, cdpLeisureTrip, password, ageSelector, returnCityCode, email, calDayMon, aciNotAuthLogin, arrivalInfoError, shortFormSun, cvvNumber, cvNumber, redirectPosContent, bookCar, railList, returnAtDifferentLocationCheckbox, no, bannerAdsFooterLink, driverAge, accept3dsTerms, forceResHomePage, countryResidence, calDayFri, corporateCustomer, corpTravelTerms, officialCompTravel, vanSiteURL, calMonthJun, cdpTripOptions, requestURL, changePickupTime, discountCode, imageUrl, urlDeliverVehicle, calDayTues, editYourItinerary, no1ClubNumber, logoUrl, h1, threeDSconfirmation, aciAuthLogin, dropOffLocation, calMonthSep, startReservation, wlClientId, clickHere, officialTravel, officialTravelButton, threeDSterms, carrentaltext, pickUp, selectedAirline, PopUpWelcome, no1ClubNo, pickupReturnLocation, calMonthAug, diffDropOff, notByPlaneTrain, shortFormDec, threeDSConfirmationProfileUpdateFail, airportList, applicantHaveDiscount, threeDTermsError, corpRate, submit, arrivalOptionError, signupSubTitle, redeem, originalRqCheckBox, corpCustomer, cdpOverlayTitle, memberIdOverlayContent, corpCustomerTravelButton, foundingDate, loginForgotPasswordNav, discountCodeHeaderCloseImgAlt, pickUpTime, inpDropoffStateCode, nvpLanguageSelected, pickUpLocation, cancel, selectPickupLocation, memberIdTrialLimitText, pleaseSelectAge, threeDStermsAfterCurrency, dropoffLocationHoursText, permissionDeniedTitle, changeDateTime, topNavSubmit, locationClosedAtPickup, lastName, shortFormMon, searchValue, threeDStitle, alternativeCDPlbtitle, noPreviousSearches, calMonthNov, flightNumber, pickUpText, shortFormFeb, wordWheelUrl, tickerSymbol, orEnterPickup, sameDropOff, backButton, viewModifyCancelLink, calMonthFeb, disCodesApplied, selectedCarType, cityList, value, urlFts4, dropOffTime, founder, addDiscountCode, arrivalInfo, locationOptions, calMonthOct, redeemOverlayTitle, parentContext, contactOption, href, continueBookingBtn, pickupLocationName, ContinueButtonContinue, CountryOfResidence, resFlowAdvisoryMsg, travelType, pickupTime, bannerAdsFooterLinkTxt, shortFormFri, returnLocation, chooseExtras, shortFormJun, memberOtherCdpField, calMonthJul, timeOutTitle, discountsLabel, dropoffHiddenEOAG, otherRentalLoc, wlAudience, deliverVehic, viewEditCancel, arrivingUpdate, calDayWed, shortFormAug, selectTime, dropOffDate, helpDeskInfoText, dtgHeader, originalResPlan, diffReturnLoc, cdpOverlayContent, calDaySat, itNumber, webContext, changePickupLocation, loadMore, cardLogo, locationSearch, EnterMemberNumber, shortFormTue, defaultTab, majorAirport, appCodeName, SignupEmail, contactType, urlHod, oneWayOverlayTitle, discountCodeHeader, popupCopyright, viewModifyCancel, forceHomepage, displayText, oneCodeApplied, editItinerary, unableToAccessResList, memberIdOverlayTitle, convNumb, inpDropoffCountryCode, threeDSpopupTitle, rightnowOverlayTitle, secDataID, closeButton, shortFormThu, yes, dropoffTime, vouchNumb, displayCDPrqAlertError, positionUnavailableTitle, modCancelRes, popupHeaderText, pageName, calDayThur, quoteNegPrice, returnTo, bookAsMember, confirmationNumber, otherConfNumber, platform, cookieMemberOnLogin, newPickUpDate, dropOffCountry, reviewAndBook, pickupLocationHoursText, topNavContactUs, SignupTCs, invalidDateError, pickupDay, maskedCC, product, urlCollectVehicle, calMonthJan, arrivalInformationLabel, shortFormSat, findLocation, timeOutFactorForWordWheel, defaultTravelType, return, AAAValidationFailed, calMonthApr, Edit, letsGo, inpPickupSearchType, ryanairHeader, inpPickupAutoFill, inpDropoffAutoFill, shortFormMar, clientDiffLocation, selectedCarLabel, loginCreateUserID, AAAMemberID, calMonthDec, apply, inpPickupStateCode, viewTripSummary, signupTitle, validPickupDate, name, phone, affiliateMemberJoin, homePageloginId, shortFormWed, shortFormOct, urlFts2, locTitle, resListEmpty, calDaySun, extendMyRental, pickUpDate, topNavCareer, telephone, threeDSCVV, urlFts1, orEnterDropoff, validDropoffDate, changePosLang, logo, headerImage, loading, locationClosed, cdpField, previousRentals, topNavCountry, collectVehic, previousSearches, continue, SignupThanks, loginForgotPassword, clearSearches, corpGovRentals, memberIdTextLabel, chooseCar, dropoffLocationName, discountOverlayTitle, locationClosedAtReturn, stateCountryList, technicalDifficulties, cdpRadioButton, ageSelectOverlayTitle, affiliateMemberID, SignupCTA, result, homePagePassword, userAgent, promoCoupon, bookAsGuest, unknownError, imageName, SignupError, inpPickupCountryCode, extendLink, searchButton, dropoffLocation, pickupHiddenEOAG, calMonthMay, pickUpCountry, reserveVan, appVersion, chooseOpenLocation, pickupLocation, shortFormJan, shortFormApr, SignupTCsURL, urlFts3, language, memberLogin, selectALocation, noArrivalInfo, shortFormMay, visitorId
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 10/51: https://www.hertz.com/rentacar/error/index.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, pos, language, id

[*] Scanning 11/51: https://www.hertz.com/rentacar/misc/?targetPage=GPR_FAQs.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, id, preview

[*] Scanning 12/51: https://www.hertz.com/rentacar/member/login/overlay
[*] Probing the target for stability
[+] Heuristic scanner found 7 parameters: loginForgotPassword, cookieMemberOnLogin, cookieMemberOnLoginInPage, loginId, password, loginCreateUserID, ca
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 13/51: https://www.hertz.com/rentacar/emember/login/index.jsp?targetPage=loginView.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, language, id, pos

[*] Scanning 14/51: https://www.hertz.com/rentacar/vehicleguide/index.jsp?targetPage=vehicleGuideHomeView.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, id, pos, language

[*] Scanning 15/51: https://www.hertz.com/rentacar/hertzlink/index.jsp?targetPage=MasterCard_Premium.xml
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, id, preview

[*] Scanning 16/51: https://www.hertz.com/rentacar/hertzlink/index.jsp?PID=7304739
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: phone
[+] Parameters found: p4ssw0rD, id, preview

[*] Scanning 17/51: https://www.hertz.com/rentacar/privacypolicy/index.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, language, pos, id

[*] Scanning 18/51: https://www.hertz.com/rentacar/partner/index.jsp
[*] Probing the target for stability
[+] Heuristic scanner found 52 parameters: displayText, loginForgotPassword, cookieMemberOnLogin, homePageloginId, parentContext, url, pos, imageUrl, contactOption, nvpLanguageSelected, rootContext, returnURL, memberLogout, topNavChange, logoUrl, value, h1, rightnowOverlayTitle, secDataID, topNavSubmit, loginId, partnerTitle, topNavContactUs, loginCreateUserID, wlClientId, founder, topNavCareer, telephone, result, homePagePassword, searchValue, changePosLang, contactType, password, language, logo, headerImage, topNavCountry, pageName, memberLogin, foundingDate, imageName, loginForgotPasswordNav, carrentaltext, returnTo, wlAudience, name, phone, searchButton, requestURL, webContext, tickerSymbol
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 19/51: https://www.hertz.com/rentacar/b2b/index.jsp?targetPage=diversityOverview.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD, language, pos, id

[*] Scanning 20/51: https://www.hertz.com/rentacar/member/login?iss=https://auth.hertz.com/
[*] Probing the target for stability
[+] Heuristic scanner found 53 parameters: displayText, loginForgotPassword, cookieMemberOnLogin, homePageloginId, parentContext, url, pos, imageUrl, contactOption, cookieMemberOnLoginInPage, nvpLanguageSelected, rootContext, returnURL, memberLogout, topNavChange, logoUrl, value, h1, rightnowOverlayTitle, secDataID, topNavSubmit, loginId, topNavContactUs, loginCreateUserID, ca, wlClientId, founder, topNavCareer, telephone, result, homePagePassword, searchValue, changePosLang, contactType, password, language, logo, headerImage, topNavCountry, pageName, memberLogin, foundingDate, imageName, loginForgotPasswordNav, carrentaltext, returnTo, wlAudience, name, phone, searchButton, requestURL, webContext, tickerSymbol
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 21/51: https://www.hertz.com/auth0-callback.model.json
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD  

[*] Scanning 22/51: https://offer.hertz.com/offers/index.jsp?targetPage=hbr-online-credit.jsp
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD  

[*] Scanning 23/51: https://offer.hertz.com/offers/assets/1758906708272/integrated/offer.js
[*] Probing the target for stability
[+] Parameters found: p4ssw0rD  

[*] Scanning 24/51: https://dvir.hertz.com/api/health-check
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters
[+] Parameters found: p4ssw0rD  

[*] Scanning 25/51: https://dvir.hertz.com/damage-selfservice/create
[*] Probing the target for stability
[+] Heuristic scanner found 6 parameters: 299509, host, page, buildId, id, maintenance
[+] Parameters found: p4ssw0rD  

[*] Scanning 26/51: https://dvir.hertz.com/damage-selfservice/login
[*] Probing the target for stability
[+] Heuristic scanner found 5 parameters: host, page, buildId, 236112, maintenance
[+] Parameters found: p4ssw0rD  

[*] Scanning 27/51: https://dvir.hertz.com/damage-selfservice/customerLogin
[*] Probing the target for stability
[+] Heuristic scanner found 7 parameters: env, host, page, buildId, 449441, serverType, maintenance
[+] Parameters found: p4ssw0rD  

[*] Scanning 28/51: https://dvir.hertz.com/damage-selfservice/link
[*] Probing the target for stability
[+] Heuristic scanner found 7 parameters: env, host, page, buildId, serverType, 342246, maintenance
[+] Parameters found: p4ssw0rD  

[*] Scanning 29/51: https://dvir.hertz.com/damage-selfservice/success
[*] Probing the target for stability
[+] Heuristic scanner found 5 parameters: host, page, buildId, 465812, maintenance
[+] Parameters found: p4ssw0rD  

[*] Scanning 30/51: https://extensions.hertz.com/index.html
[*] Probing the target for stability
[-] Server received a bad request. Try decreasing the chunk size with -c option
[-] Skipped https://extensions.hertz.com/index.html due to errors
[*] Scanning 31/51: https://ir.hertz.com/overview/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 14 parameters: __RequestVerificationAntiCSRFToken, Authorization, isoDate, StockSymbolText, __antiCSRF, time, __RequestVerificationToken, StockExchange, date, StockSymbol, StockExchangeText, hdnRedirectToLoginUrl, isoTime, __VIEWSTATE
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 32/51: https://ir.hertz.com/financials/sec-filings/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[!] No parameters were discovered.

[*] Scanning 33/51: https://ir.hertz.com/financials/quarterly-results/default.aspx
[*] Probing the target for stability
[-] Skipped https://ir.hertz.com/financials/quarterly-results/default.aspx due to errors
[*] Scanning 34/51: https://ir.hertz.com/governance/board-of-directors/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[!] No parameters were discovered.

[*] Scanning 35/51: https://ir.hertz.com/governance/committee-composition/default.aspx
[*] Probing the target for stability

[-] Skipped https://ir.hertz.com/governance/committee-composition/default.aspx due to errors
[*] Scanning 36/51: https://ir.hertz.com/governance/governance-documents/default.aspx
[*] Probing the target for stability

[-] Skipped https://ir.hertz.com/governance/governance-documents/default.aspx due to errors
[*] Scanning 37/51: https://ir.hertz.com/governance/leadership-team/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[!] No parameters were discovered.

[*] Scanning 38/51: https://ir.hertz.com/stock-info/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[!] No parameters were discovered.

[*] Scanning 39/51: https://ir.hertz.com/resources/investor-email-alerts/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[-] Encountered an error: ir.hertz.com
[-] Skipped https://ir.hertz.com/resources/investor-email-alerts/default.aspx due to errors
[*] Scanning 40/51: https://ir.hertz.com/search-results/default.aspx
[*] Probing the target for stability
[-] Encountered an error: ir.hertz.com
[-] Skipped https://ir.hertz.com/search-results/default.aspx due to errors
[*] Scanning 41/51: https://ir.hertz.com/site-map/default.aspx
[*] Probing the target for stability
[+] Heuristic scanner found 3 parameters: token, version, rayId
[!] No parameters were discovered.
[*] Scanning 1/7: https://www.hertz.com/us/en/blog
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 2/7: https://www.hertz.com/us/en/deals-and-offers
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Encountered an error: www.hertz.com
[-] Skipped https://www.hertz.com/us/en/deals-and-offers due to errors
[*] Scanning 3/7: https://www.hertz.com/us/en/checkin
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 4/7: https://www.hertz.com/us/en/reservation/lookup
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 5/7: https://www.hertz.com/us/en/programs/business-rewards
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 6/7: https://www.hertz.com/us/en/programs/rideshare-rentals/uber-drivers
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.

[*] Scanning 7/7: https://www.hertz.com/us/en/products-and-services/value-added-services/united-states
[*] Probing the target for stability
[+] Heuristic scanner found 1 parameter: name
[-] Target is misbehaving. Try the --stable swtich.
[!] No parameters were discovered.
```

# 9_Port scanner

### Tool:

- Nmap

### Command:

```
nmap -T4 -F www.hertz.com
```

### Result:

```
PORT      STATE SERVICE
21/tcp    open  ftp
25/tcp    open  smtp
37/tcp    open  time
53/tcp    open  domain
80/tcp    open  http
81/tcp    open  hosts2-ns
88/tcp    open  kerberos-sec
110/tcp   open  pop3
119/tcp   open  nntp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
389/tcp   open  ldap
443/tcp   open  https
444/tcp   open  snpp
465/tcp   open  smtps
543/tcp   open  klogin
554/tcp   open  rtsp
587/tcp   open  submission
631/tcp   open  ipp
990/tcp   open  ftps
993/tcp   open  imaps
995/tcp   open  pop3s
1025/tcp  open  NFS-or-IIS
1028/tcp  open  unknown
1029/tcp  open  ms-lsa
1433/tcp  open  ms-sql-s
1720/tcp  open  h323q931
2000/tcp  open  cisco-sccp
2001/tcp  open  dc
2049/tcp  open  nfs
2121/tcp  open  ccproxy-ftp
3000/tcp  open  ppp
3306/tcp  open  mysql
3389/tcp  open  ms-wbt-server
5000/tcp  open  upnp
5009/tcp  open  airport-admin
5051/tcp  open  ida-agent
5060/tcp  open  sip
5800/tcp  open  vnc-http
5900/tcp  open  vnc
6000/tcp  open  X11
6001/tcp  open  X11:1
7070/tcp  open  realserver
8000/tcp  open  http-alt
8008/tcp  open  http
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
8081/tcp  open  blackice-icecap
8443/tcp  open  https-alt
8888/tcp  open  sun-answerbook
9100/tcp  open  jetdirect
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt
```
