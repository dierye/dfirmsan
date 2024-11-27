# **D-Link**

+ **DIR-629-B1:**

CVE-2018-10996 :session.cgi?ACTION=logout request（command）
CVE-2018-5318 :The sprintf() function in soap.cgi spliced the HTTP_SOAPACTION field of an http request and stored it on the stack, causing a buffer overflow. (BOF)

+ **DIR-859 A3-1.06**: 

CVE-2019-17508(command injection)

+ **DIR-859 (A1) 1.05**:

CVE-2022-46476(command) CVE-2022-25106(BOF)
Passing through environment variables (ommand inject)：
CVE-2019-20217 CVE-2019-20216 CVE-2019-20215 CVE-2019-17621

+ **DIR-816 A2 1.10 B04**:

CVE-2022-28915（command） CVE-2022-29325(BOF)

+ **DIR-816 A2 1.10 B05**:

CVE-2021-31326(command)
CVE-2021-26810(command)
Buffer Over Flow:
CVE-2018-17067 goahead: /goform/formLogin
CVE-2018-17065 
CVE-2018-11013 goahead: websRedirect 

+ DGS-1210-48(switch)

+ **DIR820L A1_FW105B02**

 **ncc2**

 **[CVE-2023-25280](https://nvd.nist.gov/vuln/detail/CVE-2023-25280)**(CI)

 **[CVE-2023-25279](https://nvd.nist.gov/vuln/detail/CVE-2023-25279)**(CI)

 **[CVE-2023-25281](https://nvd.nist.gov/vuln/detail/CVE-2023-25281)**(SOF)

 **[CVE-2023-25282](https://nvd.nist.gov/vuln/detail/CVE-2023-25282)**(HOF)

# **TP-Link **

+ **TL-WR940N V4_160620**:

CVE-2023-33538(command)

CVE-2020-35575(admin access) 

CVE-2023-36356(Out-of-bounds Read) 

CVE-2023-36357(Dos) CVE-2022-46139(Dos)

**Buffer Over Flow:**

**httpd**

CVE-2017-13772 CVE-2019-6989(ipAddrDispose) CVE-2023-36358 
CVE-2023-36359 CVE-2023-33536 CVE-2023-33537 CVE-2023-36354 
[CVE-2023-36355](https://packetstormsecurity.com/files/173294/TP-Link-TL-WR940N-4-Buffer-Overflow.html)

+ **WR941ND V5**:

CVE-2023-36356(read out-of-bounds) 
CVE-2023-36357(Dos) 
Buffer Over Flow:
CVE-2023-36354 CVE-2023-36358 CVE-2023-36359 

+ **AX21(US)_V3_1.1.4 Build 20230219**

  **/usr/lib/libtmpv2.so**

  [CVE-2023-31710](https://nvd.nist.gov/vuln/detail/CVE-2023-31710)

+ **TL-WPA7510 (EU)_V2_190125**

  **httpd**

  [CVE-2023-29562](https://github.com/lzd521/IOT/tree/main/TP-Link%20WPA7510)

# **Netgear**

+ **R6400 v2_1.0.4.118**  ***Test1**

**upnp**

102-118

**[CVE-2021-34991](https://nvd.nist.gov/vuln/detail/CVE-2021-34991)**(BOF)

**[CVE-2021-45525](https://nvd.nist.gov/vuln/detail/CVE-2021-45525)**、**[CVE-2021-45527](https://nvd.nist.gov/vuln/detail/CVE-2021-45527)**、**[CVE-2021-45549](https://nvd.nist.gov/vuln/detail/CVE-2021-45549)**、**[CVE-2021-45554](https://nvd.nist.gov/vuln/detail/CVE-2021-45554)**

**[CVE-2021-45604](https://nvd.nist.gov/vuln/detail/CVE-2021-45604)**、**[CVE-2021-45606](https://nvd.nist.gov/vuln/detail/CVE-2021-45606)**、**[CVE-2021-45607](https://nvd.nist.gov/vuln/detail/CVE-2021-45607)**、**[CVE-2021-45610](https://nvd.nist.gov/vuln/detail/CVE-2021-45610)**

**[CVE-2022-48196](https://nvd.nist.gov/vuln/detail/CVE-2022-48196)**、**[CVE-2023-36187](https://nvd.nist.gov/vuln/detail/CVE-2023-36187)** 

**[CVE-2021-45608](https://nvd.nist.gov/vuln/detail/CVE-2021-45608)**（ Integer Overflow）

# Others

+ Trendnet FW_TV-IP121WN(camera)

+ Belkin（open-source）

+ Linksys WRT54GL 4.30.18.006 (open-source)

  **httpd**

  CVE-2022-43970(SOF)

  CVE-2022-43973(CI)

  CVE-2023-31742(CI)

  **upnp**

  CVE-2022-43972(null pointer dereference)

+ **Tenda AC18 v15.03.05.19**:

  **httpd**

  Comamnd: 
  CVE-2023-30135 CVE-2022-31446 CVE-2022-35201 CVE-2020-24987

+ **Totolink  A7100RU**:

  **lighthttpd**

  34 个CVE
  All Command Inject
  CVE-2023-30053 CVE-2023-30054

+ Zyxel (open-source)

+ Phicomm (RCE)

+ Mikrotik  Router OS 

​	**[CVE-2021-41987](https://nvd.nist.gov/vuln/detail/CVE-2021-41987)**

​	**[CVE-2020-22845](https://nvd.nist.gov/vuln/detail/CVE-2020-22845)**

​	**[CVE-2020-22844](https://nvd.nist.gov/vuln/detail/CVE-2020-22844)**

​	**[CVE-2018-1156](https://nvd.nist.gov/vuln/detail/CVE-2018-1156)**

​	**[CVE-2018-7445](https://nvd.nist.gov/vuln/detail/CVE-2018-7445)**



# More BOF CVEs

## Tenda 

+ **Tenda AC15 V15.03.1.16_multi**

  **[CVE-2018-5767](https://nvd.nist.gov/vuln/detail/CVE-2018-5767)**  (sscanf) 

+ **AX1803 v1.0.0.1_2890** 

​		**tdhttpd** 

​		heap over flow：**[CVE-2022-40875](https://nvd.nist.gov/vuln/detail/CVE-2022-40875)**、**[CVE-2022-40874](https://nvd.nist.gov/vuln/detail/CVE-2022-40874)**

​		stack over flow：[**CVE-2022-40876**](https://nvd.nist.gov/vuln/detail/CVE-2022-40876)、**[CVE-2022-37824](https://nvd.nist.gov/vuln/detail/CVE-2022-37824)**、**[CVE-2022-37823](https://nvd.nist.gov/vuln/detail/CVE-2022-37823)** 

​		**[CVE-2022-37822](https://nvd.nist.gov/vuln/detail/CVE-2022-37822)** 、**[CVE-2022-37821](https://nvd.nist.gov/vuln/detail/CVE-2022-37821)**、**[CVE-2022-37820](https://nvd.nist.gov/vuln/detail/CVE-2022-37820)**、**[CVE-2022-37819](https://nvd.nist.gov/vuln/detail/CVE-2022-37819)**

​		**[CVE-2022-37818](https://nvd.nist.gov/vuln/detail/CVE-2022-37818)**、**[CVE-2022-37817](https://nvd.nist.gov/vuln/detail/CVE-2022-37817)**、**[CVE-2022-30040](https://nvd.nist.gov/vuln/detail/CVE-2022-30040)**

​		https://www.cnblogs.com/L0g4n-blog/p/16695155.html 

+ **AC23 16.03.07.45** 

​	**[CVE-2023-0782](https://nvd.nist.gov/vuln/detail/CVE-2023-0782)** : The function `formSetSysToolDDNS` can set nvram's parameter `adv.ddns1.en` to ` v22`, and ` v22` ** can be set to `ddnsEn` ** via the POST parameter; in the `formGetSysToolDDNS` function, the call to `GetValue( “adv.ddns1.en”, v11)` to set the ` v11` string on the stack, so a stack overflow vulnerability exists.

+ **AC18 v15.03.05.19**  ***Test2**

​	**httpd** 
​		Buffer Over Flow:
​		[**CVE-2023-24164**](https://github.com/DrizzlingSun/Tenda/blob/main/AC18/4/4.md)、CVE-2023-24165、CVE-2023-24166、CVE-2023-24167
​		CVE-2023-24169、 **[CVE-2023-24170](https://nvd.nist.gov/vuln/detail/CVE-2023-24170)**

​		**[CVE-2022-44171](https://nvd.nist.gov/vuln/detail/CVE-2022-44171)**、**[CVE-2022-44172](https://nvd.nist.gov/vuln/detail/CVE-2022-44172)**、**[CVE-2022-44174](https://nvd.nist.gov/vuln/detail/CVE-2022-44174)**、**[CVE-2022-44175](https://nvd.nist.gov/vuln/detail/CVE-2022-44175)**、**[CVE-2022-44176](https://nvd.nist.gov/vuln/detail/CVE-2022-44176)**、**[CVE-2022-44177](https://nvd.nist.gov/vuln/detail/CVE-2022-44177)**、CVE-2022-44178、CVE-2022-44180、CVE-2022-44183

​		**[CVE-2022-43260](https://nvd.nist.gov/vuln/detail/CVE-2022-43260)**、CVE-2022-40861、CVE-2022-40854

​		**[CVE-2022-38309](https://nvd.nist.gov/vuln/detail/CVE-2022-38309)**、**[CVE-2022-38310](https://nvd.nist.gov/vuln/detail/CVE-2022-38310)**、**[CVE-2022-38311](https://nvd.nist.gov/vuln/detail/CVE-2022-38311)**、**[CVE-2022-38312](https://nvd.nist.gov/vuln/detail/CVE-2022-38312)**、**[CVE-2022-38313](https://nvd.nist.gov/vuln/detail/CVE-2022-38313)**、**[CVE-2022-38314](https://nvd.nist.gov/vuln/detail/CVE-2022-38314)**

+ **CVE-2022-38310** 

  ```c
  int sub_426A0(){
      //...
      sub_17484("SetStaticRouteCfg", fromSetRouteStatic);
      //...
  }	
  
  int __fastcall fromSetRouteStatic(int a1){
      //...
  	list = websgetvar(a1, "list", &unk_E8A34);    // Read list parameter data and pass into sub_79180 function
    	v1 = sub_79180("adv.staticroute", list, 126);
      //...
  }
  
  int __fastcall sub_79180(const char *a1, char *list, unsigned __int8 a3){
    char s1[4]; // [sp+24h] [bp-198h] BYREF
    char v9[16]; // [sp+34h] [bp-188h] BYREF
    char v10[16]; // [sp+44h] [bp-178h] BYREF
    char v11[16]; // [sp+54h] [bp-168h] BYREF
    char *src; // [sp+1ACh] [bp-10h]
    //...
    if ( strlen(list) > 4 ){
      //...
      src = list;                     // 'src' come from external input 'list'
      while ( 1 ){
        //...
        if ( sscanf(src, "%[^,],%[^,],%[^,],%s", v11, v10, v9, s1) == 4 )// No limit on length, easy to cause v11, v10, v9, s1 to overflow
        //...
      }
      //...
  }
  ```

+ **CVE-2022-38314** 

  ```c
  int sub_426A0(){
      //...
      sub_17484("saveParentControlInfo", saveParentControlInfo);
      //...
  }
  
  int __fastcall saveParentControlInfo(int a1){
      char *v18; // [sp+3ACh] [bp-50h]
      char *urls; // [sp+3C8h] [bp-34h]
      //...
      urls = (char *)websgetvar(a1, "urls", &unk_F0A08);// Read data from urls parameter
      //...
      v18 = malloc(596u);
    	memset(v18, 0, 596u);
      //..
      strcpy((char *)v18 + 80, urls);// Lack of boundary checking can easily cause v18 overflow
      //...
  }
  ```

​		**[CVE-2022-30472](https://nvd.nist.gov/vuln/detail/CVE-2022-30472)**、**[CVE-2022-30473](https://nvd.nist.gov/vuln/detail/CVE-2022-30473)**、**[CVE-2022-30474](https://nvd.nist.gov/vuln/detail/CVE-2022-30474)**、**[CVE-2022-30475](https://nvd.nist.gov/vuln/detail/CVE-2022-30475)**、**[CVE-2022-30476](https://nvd.nist.gov/vuln/detail/CVE-2022-30476)**、**[CVE-2022-30477](https://nvd.nist.gov/vuln/detail/CVE-2022-30477)**

​		【**[CVE-2018-18706](https://nvd.nist.gov/vuln/detail/CVE-2018-18706)**、**[CVE-2018-18707](https://nvd.nist.gov/vuln/detail/CVE-2018-18707)**、**[CVE-2018-18708](https://nvd.nist.gov/vuln/detail/CVE-2018-18708)**、**[CVE-2018-18709](https://nvd.nist.gov/vuln/detail/CVE-2018-18709)**、**[CVE-2018-18727](https://nvd.nist.gov/vuln/detail/CVE-2018-18727)**、**[CVE-2018-18728](https://nvd.nist.gov/vuln/detail/CVE-2018-18728)**、**[CVE-2018-18729](https://nvd.nist.gov/vuln/detail/CVE-2018-18729)**、**[CVE-2018-18730](https://nvd.nist.gov/vuln/detail/CVE-2018-18730)**、**[CVE-2018-18731](https://nvd.nist.gov/vuln/detail/CVE-2018-18731)**、**[CVE-2018-18732](https://nvd.nist.gov/vuln/detail/CVE-2018-18732)**】

## ASUS 

+ **RT-N53（version 3.0.0.4.376.3754）** ***Test3**

​		**httpd、rc**

​		[**CVE-2019-20082**](https://github.com/pr0v3rbs/CVE/tree/master/CVE-2019-20082) （Data saved to NVRAM, read in rc and cause overflow）

+ **RT-AX56U 3.0.0.4.386.44266** 

​		**[CVE-2021-40556](https://nvd.nist.gov/vuln/detail/CVE-2021-40556)**  strcat

+ **RT-N10LX Router v2.0.0.39**  ***Test4**

  **[CVE-2023-34942 ](https://nvd.nist.gov/vuln/detail/CVE-2023-34942)** 

  **[CVE-2023-34940 ](https://nvd.nist.gov/vuln/detail/CVE-2023-34940)** 

## H3C 

+ **Magic B1STV100R012** 

​		in sub_433A70() of /bin/**webs** 

​		**stack over flow**

​		**[CVE-2023-34937](https://nvd.nist.gov/vuln/detail/CVE-2023-34937)** 、**[CVE-2023-34936](https://nvd.nist.gov/vuln/detail/CVE-2023-34936)**、**[CVE-2023-34935](https://nvd.nist.gov/vuln/detail/CVE-2023-34935)**、**[CVE-2023-34934](https://nvd.nist.gov/vuln/detail/CVE-2023-34934)**

​		**[CVE-2023-34933](https://nvd.nist.gov/vuln/detail/CVE-2023-34933)**、**[CVE-2023-34932](https://nvd.nist.gov/vuln/detail/CVE-2023-34932)**、**[CVE-2023-34931](https://nvd.nist.gov/vuln/detail/CVE-2023-34931)**、**[CVE-2023-34930](https://nvd.nist.gov/vuln/detail/CVE-2023-34930)**

​		**[CVE-2023-34929](https://nvd.nist.gov/vuln/detail/CVE-2023-34929)**、**[CVE-2023-34928](https://nvd.nist.gov/vuln/detail/CVE-2023-34928)**、**[CVE-2023-34924](https://nvd.nist.gov/vuln/detail/CVE-2023-34924)**



+ **GR-1200W MiniGRW1A0V100R006** 

  /bin/**webs** 

  **stack overflow** 

  **[CVE-2022-37074](https://nvd.nist.gov/vuln/detail/CVE-2022-37074)**（sscanf）、**[CVE-2022-37073](https://nvd.nist.gov/vuln/detail/CVE-2022-37073)**、**[CVE-2022-37072](https://nvd.nist.gov/vuln/detail/CVE-2022-37072)**、**[CVE-2022-37071](https://nvd.nist.gov/vuln/detail/CVE-2022-37071)**

  **[CVE-2022-37069](https://nvd.nist.gov/vuln/detail/CVE-2022-37069)**、**[CVE-2022-37068](https://nvd.nist.gov/vuln/detail/CVE-2022-37068)**、**[CVE-2022-37067](https://nvd.nist.gov/vuln/detail/CVE-2022-37067)**、**[CVE-2022-37066](https://nvd.nist.gov/vuln/detail/CVE-2022-37066)**

  **[CVE-2022-36520](https://nvd.nist.gov/vuln/detail/CVE-2022-36520)**、**[CVE-2022-36519](https://nvd.nist.gov/vuln/detail/CVE-2022-36519)**、**[CVE-2022-36518](https://nvd.nist.gov/vuln/detail/CVE-2022-36518)**、**[CVE-2022-36517](https://nvd.nist.gov/vuln/detail/CVE-2022-36517)**

  **[CVE-2022-36516](https://nvd.nist.gov/vuln/detail/CVE-2022-36516)**、**[CVE-2022-36515](https://nvd.nist.gov/vuln/detail/CVE-2022-36515)**、**[CVE-2022-36514](https://nvd.nist.gov/vuln/detail/CVE-2022-36514)**、**[CVE-2022-36513](https://nvd.nist.gov/vuln/detail/CVE-2022-36513)**

  **[CVE-2022-36511](https://nvd.nist.gov/vuln/detail/CVE-2022-36511)**

## Totolink 

+ **A830R V4.1.2cu.5182**  ***Test5**

  **[CVE-2022-37842](https://nvd.nist.gov/vuln/detail/CVE-2022-37842)** :infostat.cgi 

  **[CVE-2022-37839](https://nvd.nist.gov/vuln/detail/CVE-2022-37839)** :Cstecgi.cgi

  **[CVE-2022-37840 ](https://nvd.nist.gov/vuln/detail/CVE-2022-37840)**:downloadfile.cgi

## Siretta 

+ **QUARTZ-GOLD** (industrial router) 

​		multiple CVEs in **DetranCLI** 

​		[**CVE-2022-40995**](https://talosintelligence.com/vulnerability_reports/TALOS-2022-1613)

​		[QUARTZ-GOLD (G5.0.1.5-221213)](https://www.siretta.com/?sdm_process_download=1&download_id=80680)  

## Others

+ **Dahua** (camera) 

​		**sonia**

​		[参考：CVE-2021-33044](https://re1own.github.io/2021/10/21/%E5%A4%A7%E5%8D%8E%E6%91%84%E5%83%8F%E5%A4%B4-CVE-2021-33044%E6%BC%8F%E6%B4%9E%E7%A0%94%E7%A9%B6/) 

+ **REOLINK RLC-410W 3.0.0.136_20121102**   

​       TestEmail() in cgiserver.cgi

​		Out-of-bounds Write

​		[CVE-2022-21217](https://nvd.nist.gov/vuln/detail/CVE-2022-21217)

​		https://vuldb.com/?id.191913

​		[firmware_RLC_410W_5MP_v300136](https://home-cdn.reolink.us/wp-content/uploads/2020/12/181032201608287540.9848.zip?download_name=firmware_RLC_410W_5MP_v300136.zip)

+ **Wyze Cam **  （Firmware encryption）

​		Wyze Cam Pan v2 versions prior to 4.49.1.47. Wyze Cam v2 versions prior to 4.9.8.1002. Wyze Cam v3 versions prior to 4.36.8.32.

​		[CVE-2019-12266](https://nvd.nist.gov/vuln/detail/CVE-2019-12266)(SOF)

​		[analysis](https://www.bitdefender.com/blog/labs/vulnerabilities-identified-in-wyze-cam-iot-device/)

​		[download](https://github.com/kohrar/Wyze-Firmwares/tree/master)

+ IPTIME 

- UTT
- FAST
- Mercury

- Cisco WAP200|WAP4410N (AP)

- Ezviz (camera)
