/* ==========================================================================
   EmailShield - Comprehensive Bilingual Translation Dictionary (English & Telugu)
   ========================================================================== */

const TRANSLATIONS = {
  en: {
    // Brand & Navigation
    brand_title: "EmailShield",
    brand_tagline: "Detect • Investigate • Stay Safe",
    platform_desc: "AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform",
    nav_home: "Home",
    nav_dashboard: "SOC Dashboard",
    nav_check_email: "Check Email",
    nav_geolocation: "GeoLocation & Infrastructure",
    nav_monitor: "Email Monitor",
    nav_alerts: "My Alerts",
    nav_cases: "Cases",
    nav_reports: "Reports",
    nav_threat_intel: "Threat Intelligence",
    nav_help: "Help",
    logged_in_as: "Logged in: Analyst Persona",
    sih_prototype: "SIH Hackathon Prototype v1.0",

    // Page Titles & Headers
    page_title_home: "Welcome to EmailShield",
    page_title_welcome: "Welcome to EmailShield",
    page_title_dashboard: "Security Operations Center (SOC) Dashboard",
    page_title_check: "Check & Analyze Email",
    page_title_check_email: "Check & Analyze Email",
    page_title_geolocation: "GeoLocation & Threat Infrastructure",
    page_title_result: "Email Threat Assessment Result",
    page_title_investigation: "SOC Forensic Investigation",
    page_title_monitor: "Live Email Monitor Simulator",
    page_title_alerts: "Security Alerts & Escalations",
    page_title_cases: "Forensic Case Repository",
    page_title_reports: "Forensic PDF Reports Center",
    page_title_intel: "Threat Intelligence Workbench",
    page_title_help: "Cybersecurity Educational Hub",

    // Welcome Page
    welcome_title: "AI-Powered Email Threat Detection & Forensic Platform",
    welcome_subtitle: "Protect yourself from phishing, spoofing, and executive fraud with instant explainable threat intelligence.",
    benefit_1_title: "Detect Suspicious Emails",
    benefit_1_desc: "Scan email headers, URLs, and senders to spot phishing before clicking.",
    benefit_2_title: "Understand Why It's Risky",
    benefit_2_desc: "Clear explanations in plain language, explaining technical indicators simply.",
    benefit_3_title: "Take Safe Action",
    benefit_3_desc: "Get immediate step-by-step guidance on how to report or delete malicious emails.",
    btn_start_check: "Check an Email Now",
    btn_view_dashboard: "Analyst Dashboard",
    btn_sim_monitor: "Simulate Email Monitor",
    why_choose_title: "Why Choose EmailShield?",
    why_choose_sub: "Evidence-centric investigation platform designed for complete clarity",

    // Dashboard
    stat_total_analyzed: "Total Emails Analyzed",
    stat_threats_detected: "Threats Detected",
    stat_high_risk: "High Risk Cases",
    stat_processed_24h: "Processed Last 24 Hours",
    chart_threat_distribution: "Threat Distribution",
    chart_realtime: "Real-Time",
    rapid_analysis_title: "Rapid Email Threat Analysis",
    rapid_analysis_desc: "Need to investigate a suspicious email received in your inbox? Use EmailShield's evidence-centric parser to break down raw headers, origin IPs, and URLs.",
    upload_eml_title: "Upload EML File",
    upload_eml_sub: "Inspect .eml headers safely in sandbox",
    live_monitor_title: "Live Inbox Monitor",
    live_monitor_sub: "Simulate real-time inbox threat stream",
    recent_investigations_title: "Recent Forensic Investigations",
    demo_data_notice: "Synthetic Demo Data Included",
    table_case_id: "Case ID",
    table_subject: "Subject / Title",
    table_classification: "Classification",
    table_risk_score: "Risk Score",
    table_analyzed_at: "Analyzed At",
    table_action: "Action",

    // Check Email Page
    check_title: "Analyze Suspicious Email",
    check_subtitle: "Upload an .eml file or paste raw email headers to begin forensic investigation.",
    sample_demo_label: "Try Sample Demonstrations (Hackathon Demo):",
    sample_demo_sub: "Instant one-click pre-configured sample emails",
    btn_sample_phishing: "Load Phishing Sample",
    btn_sample_suspicious: "Load Suspicious Sample",
    btn_sample_safe: "Load Safe Sample",
    method_1_title: "Method 1: Upload .eml File",
    method_1_desc: "Select or drag standard .eml raw RFC822 email files exported from Outlook, Gmail, or Thunderbird.",
    method_1_drag: "Drag & drop an .eml file here, or click to browse",
    method_1_limit: "Supported format: .eml (Max size: 5MB)",
    btn_upload_analyze: "Upload & Analyze File",
    method_2_title: "Method 2: Paste Raw Email Content",
    method_2_desc: "Paste full raw email headers and body text directly into the forensic sandbox.",
    paste_placeholder: "Paste complete raw email headers and body text here...",
    btn_analyze_threat: "Analyze Email Threat",

    // Normal User Result Page
    status_threat: "Potential Threat Detected",
    status_threat_desc: "This email shows strong indicators of being dangerous or fake.",
    status_suspicious: "Suspicious Email",
    status_suspicious_desc: "This email contains suspicious elements. Proceed with extreme caution.",
    status_safe: "Legitimate / Safe Email",
    status_safe_desc: "No significant threat indicators were detected in this email.",
    why_header: "Why was this email flagged?",
    action_header: "What should you do?",
    action_danger_1: "Do not click any links or download attachments from this email.",
    action_danger_2: "Do not provide passwords, OTPs, or financial information.",
    action_danger_3: "Report this email to your administrator or security team immediately.",
    action_safe_1: "This email appears safe, but always verify unexpected requests.",
    btn_detailed_investigation: "View Detailed SOC Investigation",
    btn_report_email: "Report Email",
    btn_check_another: "Check Another Email",

    // Analyst Investigation Tabs
    tab_overview: "Overview",
    tab_headers: "Raw Headers",
    tab_auth: "Authentication (SPF/DKIM/DMARC)",
    tab_urls: "URLs & Domains",
    tab_geo: "IP & Geolocation Map",
    tab_timeline: "Forensic Timeline",
    tab_graph: "Investigation Graph",
    tab_report: "Report & Notes",
    pdf_report_btn: "PDF Report",
    download_pdf_btn: "Download Complete PDF Report",
    add_note_btn: "Add Note",
    note_placeholder: "Add forensic observation or mitigation notes...",

    // Live Email Monitor
    simulated_monitor_title: "Simulated Real-Time Email Monitor",
    simulated_monitor_desc: "Simulates inbound email traffic ingestion, continuous automated threat evaluation, and real-time alert generation.",
    btn_start_monitor: "Start Live Monitoring",
    btn_pause_monitor: "Pause Monitoring",
    btn_trigger_sample: "Trigger Sample Email",
    monitor_demo_notice: "Demo Environment Notice: This is a synthetic Email Monitor simulation environment designed for hackathon demonstration.",
    live_inbound_stream: "Live Inbound Email Stream",

    // Help & Education
    help_title: "Cybersecurity Educational Hub",
    help_subtitle: "Learn how email threats work and stay safe online.",
    q1_title: "What is Phishing?",
    q1_desc: "Phishing is a fraudulent attempt to steal sensitive information such as usernames, passwords, and credit card details by impersonating a trustworthy entity.",
    q2_title: "What is Email Spoofing?",
    q2_desc: "Email spoofing occurs when an attacker forged the email header From address so that the message appears to originate from someone else.",
    q3_title: "What are SPF, DKIM, and DMARC?",
    q3_desc: "These are email authentication standards. SPF verifies sender IP authorization, DKIM adds a digital signature, and DMARC instructs mail servers on how to handle failed checks.",
    q4_title: "What is IP Geolocation?",
    q4_desc: "IP Geolocation maps an IP address to an approximate physical location. Note: IP location is approximate and represents mail server routing, not necessarily the actual sender person."
  },

  te: {
    // Brand & Navigation
    brand_title: "ఈమెయిల్ షీల్డ్ (EmailShield)",
    brand_tagline: "గుర్తించండి • విచారించండి • సురక్షితంగా ఉండండి",
    platform_desc: "AI ఆధారిత ఈమెయిల్ బెదిరింపు గుర్తింపు మరియు ఫోరెన్సిక్ ఇన్వెస్టిగేషన్ వేదిక",
    nav_home: "ముఖ్య పేజీ",
    nav_dashboard: "SOC డాష్‌బోర్డ్",
    nav_check_email: "ఈమెయిల్ తనిఖీ",
    nav_geolocation: "స్థాన నిర్ధారణ మ్యాప్ (GeoLocation)",
    nav_monitor: "లైవ్ మానిటర్",
    nav_alerts: "హెచ్చరికలు",
    nav_cases: "కేసులు",
    nav_reports: "PDF నివేదికలు",
    nav_threat_intel: "బెదిరింపుల సమాచారం",
    nav_help: "సహాయం & అవగాహన",
    logged_in_as: "లాగిన్ అయ్యారు: విశ్లేషకుల మోడ్",
    sih_prototype: "SIH హ్యాకథాన్ ప్రోటోటైప్ v1.0",

    // Page Titles & Headers
    page_title_welcome: "ఈమెయిల్ షీల్డ్‌కి స్వాగతం",
    page_title_dashboard: "సెక్యూరిటీ ఆపరేషన్స్ సెంటర్ (SOC) డాష్‌బోర్డ్",
    page_title_check: "ఈమెయిల్ పరిశీలన మరియు విశ్లేషణ",
    page_title_geolocation: "స్థాన నిర్ధారణ & ప్రాథమిక సౌకర్యాలు (GeoLocation)",
    page_title_result: "ఈమెయిల్ భద్రతా విశ్లేషణ ఫలితం",
    page_title_investigation: "పూర్తి ఫోరెన్సిక్ ఇన్వెస్టిగేషన్ (SOC Mode)",
    page_title_monitor: "లైవ్ ఈమెయిల్ మానిటర్ సిమ్యులేటర్",
    page_title_alerts: "సెక్యూరిటీ హెచ్చరికల నిర్వహణ",
    page_title_cases: "ఇన్వెస్టిగేషన్ కేసుల నిర్వహణ",
    page_title_reports: "PDF నివేదికల కేంద్రం",
    page_title_intel: "బెదిరింపుల సమాచార వేదిక",
    page_title_help: "సైబర్ సెక్యూరిటీ అవగాహన కేంద్రం",

    // Welcome Page
    welcome_title: "AI ఆధారిత ఈమెయిల్ భద్రతా గుర్తింపు వేదిక",
    welcome_subtitle: "ఫిషింగ్, నకిలీ ఈమెయిళ్ళు మరియు ఆర్థిక మోసాల నుండి మిమ్మల్ని మీరు సురక్షితంగా ఉంచుకోండి.",
    benefit_1_title: "సందేహాస్పద ఈమెయిళ్లను గుర్తించండి",
    benefit_1_desc: "లింక్‌లపై క్లిక్ చేయడానికి ముందే ఈమెయిల్ శీర్షికలు, URL లు మరియు పంపినవారిని స్కాన్ చేయండి.",
    benefit_2_title: "అపాయం ఎందుకో అర్థం చేసుకోండి",
    benefit_2_desc: "సంక్లిష్ట సాంకేతిక వివరాలను సరళమైన తెలుగు భాషలో స్పష్టంగా తెలుసుకోండి.",
    benefit_3_title: "సురక్షిత చర్యలు తీసుకోండి",
    benefit_3_desc: "ప్రమాదకరమైన ఈమెయిళ్లను రిపోర్ట్ చేయడానికి సులభమైన మార్గదర్శకత్వం పొందండి.",
    btn_start_check: "ఈమెయిల్ ని తనిఖీ చేయండి",
    btn_view_dashboard: "విశ్లేషకుల డాష్‌బోర్డ్",
    btn_sim_monitor: "లైవ్ ఈమెయిల్ మానిటర్",
    why_choose_title: "EmailShield ను ఎందుకు ఎంచుకోవాలి?",
    why_choose_sub: "స్పష్టమైన ఆధారాలతో కూడిన భద్రతా విచారణ వేదిక",

    // Dashboard
    stat_total_analyzed: "మొత్తం పరిశీలించిన ఈమెయిళ్ళు",
    stat_threats_detected: "గుర్తించిన అపాయాలు",
    stat_high_risk: "తీవ్రమైన ప్రమాద కేసులు",
    stat_processed_24h: "గత 24 గంటల్లో విశ్లేషించినవి",
    chart_threat_distribution: "అపాయ వర్గీకరణ",
    chart_realtime: "రియల్-టైమ్",
    rapid_analysis_title: "వేగవంతమైన ఈమెయిల్ విశ్లేషణ",
    rapid_analysis_desc: "మీ వద్ద ఉన్న సందేహాస్పద ఈమెయిల్‌ను తనిఖీ చేయాలనుకుంటున్నారా? EmailShield ద్వారా ఈమెయిల్ హెడర్‌లు, IP అడ్రెస్‌లు మరియు URL లను తక్షణమే విశ్లేషించండి.",
    upload_eml_title: "EML ఫైల్ అప్‌లోడ్ చేయండి",
    upload_eml_sub: ".eml హెడర్‌లను సురక్షితంగా విశ్లేషించండి",
    live_monitor_title: "లైవ్ ఇన్బాక్స్ మానిటర్",
    live_monitor_sub: "ఈమెయిల్ బెదిరింపులను లైవ్‌లో పరిశీలించండి",
    recent_investigations_title: "ఇటీవల జరిపిన ఇన్వెస్టిగేషన్లు",
    demo_data_notice: "డెమో డేటా చేర్చబడింది",
    table_case_id: "కేస్ ఐడి",
    table_subject: "విషయం / శీర్షిక",
    table_classification: "వర్గీకరణ",
    table_risk_score: "ప్రమాద స్కోరు",
    table_analyzed_at: "విశ్లేషించిన సమయం",
    table_action: "చర్య",

    // Check Email Page
    check_title: "సందేహాస్పద ఈమెయిల్ పరిశీలన",
    check_subtitle: ".eml ఫైల్‌ను అప్‌లోడ్ చేయండి లేదా ఈమెయిల్ వివరాలను ఇక్కడ పేస్ట్ చేయండి.",
    sample_demo_label: "ఉదాహరణ ఈమెయిళ్లను ప్రయత్నించండి (డెమో కోసం):",
    sample_demo_sub: "ఒకే క్లిక్‌తో ప్రయత్నించే నమూనాలు",
    btn_sample_phishing: "ఫిషింగ్ నమూనా ప్రయత్నించండి",
    btn_sample_suspicious: "సందేహాస్పద నమూనా ప్రయత్నించండి",
    btn_sample_safe: "సురక్షిత నమూనా ప్రయత్నించండి",
    method_1_title: "పద్ధతి 1: .eml ఫైల్‌ను అప్‌లోడ్ చేయండి",
    method_1_desc: "Outlook, Gmail లేదా Thunderbird నుండి డౌన్‌లోడ్ చేసిన .eml ఫైళ్లను అప్‌లోడ్ చేయండి.",
    method_1_drag: ".eml ఫైల్‌ను ఇక్కడకి లాగండి లేదా క్లిక్ చేయండి",
    method_1_limit: "మద్దతు ఇచ్చే ఫార్మాట్: .eml (గరిష్ట పరిమాణం: 5MB)",
    btn_upload_analyze: "ఫైల్ అప్‌లోడ్ చేసి విశ్లేషించండి",
    method_2_title: "పద్ధతి 2: ఈమెయిల్ పాఠాన్ని ఇక్కడ పేస్ట్ చేయండి",
    method_2_desc: "ఈమెయిల్ పూర్తి పాఠాన్ని ఇక్కడ పేస్ట్ చేయండి.",
    paste_placeholder: "ఈమెయిల్ పూర్తి సమాచారాన్ని ఇక్కడ పేస్ట్ చేయండి...",
    btn_analyze_threat: "ఈమెయిల్ విశ్లేషణ ప్రారంభించండి",

    // Normal User Result Page
    status_threat: "ప్రమాదకరమైన ఈమెయిల్ (Potential Threat)",
    status_threat_desc: "ఈ ఈమెయిల్‌లో తీవ్రమైన ఫిషింగ్ మరియు ప్రమాదకర సంకేతాలు ఉన్నాయి.",
    status_suspicious: "సందేహాస్పద ఈమెయిల్ (Suspicious Email)",
    status_suspicious_desc: "ఈ ఈమెయిల్‌లో కొన్ని సందేహాస్పద వివరాలు ఉన్నాయి. జాగ్రత్తగా ఉండండి.",
    status_safe: "సురక్షితమైన ఈమెయిల్ (Legitimate / Safe)",
    status_safe_desc: "ఈ ఈమెయిల్‌లో ఎటువంటి ప్రమాదకర సంకేతాలు కనిపించలేదు.",
    why_header: "ఈ ఈమెయిల్ ఎందుకు ప్రమాదకరమైనది?",
    action_header: "మీరు ఏమి చేయాలి?",
    action_danger_1: "ఈ ఈమెయిల్‌లో ఉన్న లింక్‌లను క్లిక్ చేయవద్దు మరియు ఫైళ్లను డౌన్‌లోడ్ చేయవద్దు.",
    action_danger_2: "మీ పాస్‌వర్డ్‌లు, OTPలు లేదా బ్యాంకింగ్ వివరాలను ఎవరికీ పంచుకోవద్దు.",
    action_danger_3: "ఈ ఈమెయిల్‌ను వెంటనే మీ సంస్థ యొక్క సైబర్ సెక్యూరిటీ టీమ్‌కు రిపోర్ట్ చేయండి.",
    action_safe_1: "ఈ ఈమెయిల్ సురక్షితమైనదిగా కనిపిస్తోంది, అయితే అపరిచిత అభ్యర్థనల పట్ల జాగ్రత్తగా ఉండండి.",
    btn_detailed_investigation: "పూర్తి ఫోరెన్సిక్ ఇన్వెస్టిగేషన్ చూడండి (SOC Mode)",
    btn_report_email: "ఈమెయిల్ రిపోర్ట్ చేయండి",
    btn_check_another: "మరొక ఈమెయిల్ తనిఖీ చేయండి",

    // Analyst Investigation Tabs
    tab_overview: "అవలోకనం",
    tab_headers: "రా హెడర్‌లు",
    tab_auth: "ఆథెంటికేషన్ (SPF/DKIM/DMARC)",
    tab_urls: "లింకులు మరియు డొమైన్‌లు",
    tab_geo: "IP స్థాన మ్యాప్",
    tab_timeline: "ఫోరెన్సిక్ టైమ్‌లైన్",
    tab_graph: "ఇన్వెస్టిగేషన్ గ్రాఫ్",
    tab_report: "రిపోర్ట్ & నోట్స్",
    pdf_report_btn: "PDF నివేదిక",
    download_pdf_btn: "పూర్తి PDF నివేదిక డౌన్‌లోడ్ చేయండి",
    add_note_btn: "నోట్ జోడించండి",
    note_placeholder: "మీ ఇన్వెస్టిగేషన్ నోట్స్ ఇక్కడ రాయండి...",

    // Live Email Monitor
    simulated_monitor_title: "లైవ్ ఈమెయిల్ మానిటర్ సిమ్యులేటర్",
    simulated_monitor_desc: "ఈమెయిళ్ల రాకను, స్వయంచాలక బెదిరింపు విశ్లేషణను మరియు హెచ్చరికలను లైవ్‌లో అనుకరించును.",
    btn_start_monitor: "లైవ్ మానిటరింగ్ ప్రారంభించండి",
    btn_pause_monitor: "మానిటరింగ్ నిలిపివేయండి",
    btn_trigger_sample: "సాంపుల్ ఈమెయిల్ పంపండి",
    monitor_demo_notice: "డెమో గమనిక: ఇది హ్యాకథాన్ ప్రదర్శన కోసం రూపొందించబడిన సిమ్యులేటర్.",
    live_inbound_stream: "ప్రత్యక్ష ఈమెయిల్ స్ట్రీమ్",

    // Help & Education
    help_title: "సైబర్ సెక్యూరిటీ అవగాహన కేంద్రం",
    help_subtitle: "ఈమెయిల్ బెదిరింపులను ఎలా గుర్తించాలో మరియు సురక్షితంగా ఎలా ఉండాలో తెలుసుకోండి.",
    q1_title: "ఫిషింగ్ (Phishing) అంటే ఏమిటి?",
    q1_desc: "నమ్మదగిన సంస్థ లేదా వ్యక్తిలా నటిస్తూ మీ పాస్‌వర్డ్‌లు, క్రెడిట్ కార్డ్ వివరాలను దొంగిలించడానికి చేసే మోసాన్ని ఫిషింగ్ అంటారు.",
    q2_title: "ఈమెయిల్ స్పూఫింగ్ (Email Spoofing) అంటే ఏమిటి?",
    q2_desc: "పంపినవారి ఈమెయిల్ అడ్రెస్‌ను మార్చి, వేరొకరి నుండి వచ్చినట్లు భ్రమ కలిగించే మోసాన్ని స్పూఫింగ్ అంటారు.",
    q3_title: "SPF, DKIM, మరియు DMARC అంటే ఏమిటి?",
    q3_desc: "ఇవి ఈమెయిల్ ప్రామాణీకరణ కొలమానాలు (Email Authentication). ఇవి ఈమెయిల్ నిజమైన సర్వర్ నుండి వచ్చిందో లేదో నిర్ధారిస్తాయి.",
    q4_title: "IP Geolocation అంటే ఏమిటి?",
    q4_desc: "IP Geolocation అంటే ఒక IP అడ్రస్ ఆధారంగా అది ఏ ప్రాంతానికి చెందినదో అంచనా వేయడం. ఇది సర్వర్ స్థానాన్ని చూపుతుంది."
  }
};

function getLanguage() {
  return localStorage.getItem('emailshield_lang') || 'en';
}

function setLanguage(lang) {
  if (lang !== 'en' && lang !== 'te') lang = 'en';
  localStorage.setItem('emailshield_lang', lang);
  applyTranslations();
  updateLangButtonState();
}

function applyTranslations() {
  const currentLang = getLanguage();
  const dict = TRANSLATIONS[currentLang] || TRANSLATIONS['en'];

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
        el.placeholder = dict[key];
      } else {
        el.innerText = dict[key];
      }
    }
  });
}

function updateLangButtonState() {
  const currentLang = getLanguage();
  document.querySelectorAll('.lang-btn').forEach(btn => {
    if (btn.getAttribute('data-lang') === currentLang) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  applyTranslations();
  updateLangButtonState();
});
