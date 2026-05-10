import subprocess
import re
import json
import os
import sys
from groq import Groq


# load susi dictionary
SUSI_PATH = os.path.join(os.path.dirname(__file__), "susi_dictionary.json")
with open(SUSI_PATH) as f:
    SUSI = json.load(f)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.environ.get("FLOWDROID_DATA_DIR", PROJECT_ROOT)
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
ANDROID_PLATFORMS = os.environ.get("ANDROID_PLATFORMS", "/opt/android-sdk/platforms/")

def analyze_apk(apk_path):
    FLOWDROID_JAR_PATH = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../FlowDroid/soot-infoflow-cmd-2.13.0-jar-with-dependencies.jar")
    )
    FLOWDROID_JAR_PATH_SS = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../FlowDroid/SourcesAndSinks.txt")
    )
    command = [
        "java", "-jar", FLOWDROID_JAR_PATH,
        "-a", apk_path,
        "-p", ANDROID_PLATFORMS,
        "-s", FLOWDROID_JAR_PATH_SS
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    output = result.stdout + result.stderr
    print(output)
    return output

def parse_output(output):
    leaks = []
    leak_count = 0

    # find total leak count
    count_match = re.search(r"Found (\d+) leaks", output)
    if count_match:
        leak_count = int(count_match.group(1))
	# find each leak
    sink_pattern = re.compile(r"The sink (.*?) in method <(.*?)>")
    source_pattern = re.compile(r"- \$.*?<(.*?)>")
	    
    sink_matches = sink_pattern.findall(output)
    source_matches = source_pattern.findall(output)
    
    # pair each source with its sink
    for i in range(len(sink_matches)):
        source = source_matches[i] if i < len(source_matches) else "unknown"
        sink = sink_matches[i][0]
        location = sink_matches[i][1]

        risk = calculate_risk(source, sink, len(sink_matches))

        leak = {
            "source_node": {
                "signature": source,
                "data_category": risk["source_category"]
            },
            "intermediate_node": {
                "method": location
            },
            "sink_node": {
                "signature": sink,
                "sink_category": risk["sink_category"]
            },
            "risk_node": {
                "scores": risk["scores"],
                "total": risk["total"],
                "level": risk["level"],
                "label": risk["label"]
            }
        }
        leaks.append(leak)
        
    return {
        "leak_count": leak_count,
        "leaks": leaks
    }
    
def summarize_with_llm(report):
    if not os.environ.get("GROQ_API_KEY"):
        return "Summary unavailable because GROQ_API_KEY is not configured."

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    
    prompt = f"""
    Given these Android app taint analysis results, explain in 2-3 sentences
    in plain english what sensitive data is leaking and what the privacy risk is.
    Write it for a non technical user.
    
    App: {report['app']}
    Leaks found: {report['leak_count']}
    Details: {json.dumps(report['leaks'], indent=2)}
    """
    
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}]
    )
    
    return response.choices[0].message.content
    
def clean_signature(sig):
        # extract just the class:method part
        match = re.search(r"<(.*?)>", sig)
        if match:
            return match.group(1)
        return sig
    
def llm_classify_sink(sig):
    clean = clean_signature(sig)
    
    # load cache
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, "sink_cache.json")
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)
    else:
        cache = {}
    
    # return cached result if exists
    if clean in cache:
        return cache[clean]

    if not os.environ.get("GROQ_API_KEY"):
        return "UNKNOWN"
    
    # ask LLM
    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    prompt = f"""You are an Android security expert.
    Given this Android method signature:
    {clean}

    Classify it into exactly ONE of these sink categories based on what the method DOES technically, not the app name:

    NETWORK - sends data over internet (HTTP, URL, Socket)
    LOG - writes to Android logs
    FILE - writes to file system
    DATABASE - writes to SQLite or database
    SMS_MMS - sends SMS or MMS messages (SmsManager methods only)
    PHONE_CONNECTION - makes phone calls
    VOIP - voice over IP calls
    EMAIL - sends email
    BLUETOOTH - sends via bluetooth
    ACCOUNT_SETTINGS - modifies account settings
    AUDIO - audio output
    SYNCHRONIZATION_DATA - sync operations
    CONTACT_INFORMATION - writes to contacts
    CALENDAR_INFORMATION - writes to calendar
    SYSTEM_SETTINGS - modifies system settings
    NFC - NFC transmission
    IPC - sends data to another app via Intent (startActivity, sendBroadcast, startService)
    NO_CATEGORY - none of the above

    Reply with ONLY the category name, nothing else."""

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}]
    )
    
    category = response.choices[0].message.content.strip()
    
    # save to cache
    cache[clean] = category
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)
    
    return category
    
    
def calculate_risk(source, sink, leak_count):
    score = 0
    scores = {
        "sensitive_source": 0,
        "local_storage": 0,
        "network": 0,
        "multiple_sinks": 0
    }
    
    source_clean = clean_signature(source)
    sink_clean = clean_signature(sink)

     # look up source category
    source_category = SUSI["sources"].get(source_clean, None)
    if source_category and source_category != "NO_CATEGORY":
        scores["sensitive_source"] = 3

    # look up sink category
    sink_category = SUSI["sinks"].get(sink_clean, None)

    # if not found in SuSi use fallback
    if not sink_category:
        sink_category = llm_classify_sink(sink_clean)

    # now score the sink category
    if sink_category:
        if sink_category in ["FILE", "DATABASE", "SYNCHRONIZATION_DATA"]:
            scores["local_storage"] = 1
        elif sink_category in ["NETWORK", "SMS_MMS", "PHONE_CONNECTION",
                                "EMAIL", "VOIP", "BLUETOOTH", "IPC"]:
            scores["network"] = 3

    # multiple sinks from same source
    if leak_count > 1:
        scores["multiple_sinks"] = 2

    total = sum(scores.values())

    # map to risk level
    if total <= 2:
        level, label = "R1", "Very Low"
    elif total <= 4:
        level, label = "R2", "Low"
    elif total <= 6:
        level, label = "R3", "Moderate"
    elif total <= 8:
        level, label = "R4", "High"
    elif total <= 10:
        level, label = "R5", "Very High"
    else:
        level, label = "R6", "Critical"

    return {
        "scores": scores,
        "total": total,
        "source_category": source_category or "UNKNOWN",
        "sink_category": sink_category or "UNKNOWN",
        "level": level,
        "label": label
    }
    
def run(apk_path, original_filename=None):
    app_name = original_filename or os.path.basename(apk_path)
    print(f"Analyzing {app_name}...")
    
    output = analyze_apk(apk_path)
    print(output[:500])
    report = parse_output(output)
    report["app"] = app_name
    report["summary"] = summarize_with_llm(report)
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    output_path = os.path.join(REPORTS_DIR, f"{app_name}.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"Done! Found {report['leak_count']} leaks")
    print(f"Report saved to {output_path}")

if __name__ == "__main__":
    run(sys.argv[1])
