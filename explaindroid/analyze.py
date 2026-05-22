import subprocess
import re
import json
import os
import shlex
import sys
from glob import glob
from groq import Groq

try:
    from . import config
except ImportError:
    import config


# load susi dictionary
SUSI_PATH = os.path.join(os.path.dirname(__file__), "susi_dictionary.json")
with open(SUSI_PATH) as f:
    SUSI = json.load(f)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = config.REPORTS_DIR
CACHE_DIR = config.CACHE_DIR
GROQ_MODEL = config.GROQ_MODEL
ANDROID_PLATFORMS = config.ANDROID_PLATFORMS
JAVA_BIN = config.JAVA_BIN


class FlowDroidAnalysisError(RuntimeError):
    pass


def flowdroid_paths():
    if config.FLOWDROID_JAR_PATH:
        analyzer_jar_path = os.path.abspath(config.FLOWDROID_JAR_PATH)
    else:
        candidates = sorted(glob(os.path.abspath(os.path.join(
            os.path.dirname(__file__),
            "../FlowDroid/soot-infoflow-cmd-*-jar-with-dependencies.jar"
        ))))
        if not candidates:
            raise FileNotFoundError("No FlowDroid command jar found in FlowDroid/")
        analyzer_jar_path = candidates[-1]

    sources_and_sinks_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../FlowDroid/SourcesAndSinks.txt")
    )
    return analyzer_jar_path, sources_and_sinks_path


def build_flowdroid_command(apk_path, extra_args=None):
    analyzer_jar_path, sources_and_sinks_path = flowdroid_paths()
    command = [JAVA_BIN]
    if config.JAVA_MAX_HEAP_MB > 0:
        command.append(f"-Xmx{config.JAVA_MAX_HEAP_MB}m")
    command.extend([
        "-jar", analyzer_jar_path,
        "-a", apk_path,
        "-p", ANDROID_PLATFORMS,
        "-s", sources_and_sinks_path,
    ])
    if config.PROCESS_MULTIPLE_DEX:
        command.append("-d")
    if config.LENIENT_PARSING:
        command.append("-lp")
    if config.FLOWDROID_EXTRA_ARGS:
        command.extend(shlex.split(config.FLOWDROID_EXTRA_ARGS))
    if extra_args:
        command.extend(shlex.split(extra_args))
    return command


def is_flowdroid_failure(output, returncode):
    return (
        returncode != 0
        or "Unable to locate a Java Runtime" in output
        or "The data flow analysis has failed" in output
        or "Error when looking for XML resource files in apk" in output
    )


def should_retry_without_callbacks(output):
    callback_failures = [
        "cannot set body for non-concrete method",
        "Could not calculate callback methods",
        "Error while calculating callback methods",
    ]
    return any(message in output for message in callback_failures)


def has_partial_component_results(output):
    return bool(re.search(r"Found \d+ leaks for component", output))


def summarize_flowdroid_failure(output, returncode=0):
    trimmed = output.strip()
    if "Unable to locate a Java Runtime" in output:
        return "Java runtime was not available to FlowDroid."
    if "Android platform directory" in output and "does not exist" in output:
        match = re.search(r"Android platform directory '([^']+)' does not exist", output)
        path = match.group(1) if match else ANDROID_PLATFORMS
        return f"FlowDroid could not find Android SDK platforms at {path}."
    if "File format violation in type spec table" in output:
        detail_match = re.search(r"File format violation in type spec table:[^\n]+", output)
        detail = detail_match.group(0) if detail_match else "resource table format violation"
        return (
            "FlowDroid/Soot could not parse this APK's Android resources. "
            f"{detail}. Try a smaller/older APK or a newer FlowDroid/Soot build."
        )
    if "Error when looking for XML resource files in apk" in output:
        return "FlowDroid/Soot could not parse XML resource files in this APK."
    if should_retry_without_callbacks(output):
        return (
            "FlowDroid/Soot failed while constructing Android callbacks for this APK. "
            "Install the matching Android SDK platform or run the no-callback fallback."
        )
    if "Multiple dex files detected" in output and "only processing 'classes.dex'" in output:
        return "FlowDroid detected multiple dex files but did not process all of them. Enable dex merging."
    if "The data flow analysis has failed" in output:
        match = re.search(r"The data flow analysis has failed\. Error message: ([^\n]+)", output)
        if match:
            return f"FlowDroid analysis failed: {match.group(1)}"
        return "FlowDroid data-flow analysis failed."
    if returncode != 0:
        return f"FlowDroid exited with code {returncode}. {trimmed[:1000]}"
    return trimmed[:1000] or "FlowDroid analysis failed."


def run_flowdroid_command(command, timeout_seconds=None):
    print("Running FlowDroid command:", " ".join(shlex.quote(part) for part in command))
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"FlowDroid analysis timed out after {timeout_seconds} seconds"
        ) from exc


def analyze_apk(apk_path, timeout_seconds=None):
    command = build_flowdroid_command(apk_path)
    result = run_flowdroid_command(command, timeout_seconds=timeout_seconds)
    output = result.stdout + result.stderr
    print(output)

    if is_flowdroid_failure(output, result.returncode):
        fallback_args = getattr(config, "FLOWDROID_FALLBACK_ARGS", "")
        if fallback_args and should_retry_without_callbacks(output):
            print(
                "FlowDroid callback construction failed; "
                f"retrying with fallback args: {fallback_args}"
            )
            fallback_command = build_flowdroid_command(
                apk_path,
                extra_args=fallback_args,
            )
            fallback_result = run_flowdroid_command(
                fallback_command,
                timeout_seconds=timeout_seconds,
            )
            fallback_output = fallback_result.stdout + fallback_result.stderr
            print(fallback_output)
            if not is_flowdroid_failure(fallback_output, fallback_result.returncode):
                return fallback_output, fallback_analysis_mode(fallback_args)
            if has_partial_component_results(fallback_output):
                return fallback_output, "partial_component_fallback"

        raise FlowDroidAnalysisError(
            summarize_flowdroid_failure(output, result.returncode)
        )
    return output, "default"


def fallback_analysis_mode(fallback_args):
    args = set(shlex.split(fallback_args))
    if "-ot" in args and "-nc" in args:
        return "component_no_callbacks"
    if "-nc" in args:
        return "fallback_no_callbacks"
    if "-ot" in args:
        return "component_fallback"
    return "fallback"

def parse_output(output):
    leaks = []
    leak_count = 0

    # find total leak count
    component_counts = [
        int(count)
        for count in re.findall(r"Found (\d+) leaks for component", output)
    ]
    total_match = re.search(r"^.*?Found (\d+) leaks\s*$", output, flags=re.MULTILINE)
    count_match = total_match or re.search(r"Found (\d+) leaks", output)
    if count_match:
        leak_count = int(count_match.group(1))
    if component_counts and not total_match:
        leak_count = sum(component_counts)
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
        intermediate_role = infer_intermediate_role(location)
        sink_role = infer_sink_role(risk["sink_category"])

        leak = {
            "source_node": {
                "type": "Source",
                "signature": source,
                "data_category": risk["source_category"],
                "permission": risk["permission"]
            },
            "intermediate_node": {
                "type": "Intermediate",
                "method": location,
                "role": intermediate_role
            },
            "sink_node": {
                "type": "Sink",
                "signature": sink,
                "sink_category": risk["sink_category"],
                "role": sink_role
            },
            "context_node": {
                "type": "Context",
                "component": extract_component(location),
                "path_length": 3,
                "operations": [intermediate_role, sink_role],
                "edge_types": ["FlowsTo", "FlowsTo", "Requires", "Explains", "LeadsTo"],
                "permission": risk["permission"]
            },
            "risk_node": {
                "type": "Risk",
                "scores": risk["scores"],
                "total": risk["total"],
                "level": risk["level"],
                "label": risk["label"],
                "interpretation": risk["interpretation"],
                "recommended_action": risk["recommended_action"]
            }
        }
        leaks.append(leak)
        
    return {
        "leak_count": leak_count,
        "leaks": leaks
    }
    
def summarize_with_llm(report):
    if report.get("leak_count", 0) == 0:
        return (
            "FlowDroid did not detect any configured source-to-sink privacy leaks "
            "in this run. This does not prove the APK is secure; it means no leaks "
            "matched the current analyzer configuration and source/sink list."
        )

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
    
    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as exc:
        return f"Summary unavailable because the LLM request failed: {exc}"
    
def clean_signature(sig):
        # extract just the class:method part
        match = re.search(r"<(.*?)>", sig)
        if match:
            return match.group(1)
        return sig


def extract_component(method):
    match = re.match(r"([^:]+):", method or "")
    return match.group(1) if match else "Unknown component"


def infer_intermediate_role(method):
    text = (method or "").lower()
    if any(token in text for token in ("send", "post", "http", "request", "upload")):
        return "Transmission preparation"
    if any(token in text for token in ("put", "insert", "save", "write", "store")):
        return "Storage"
    if any(token in text for token in ("get", "fetch", "load", "read")):
        return "Retrieval"
    if any(token in text for token in ("json", "serialize", "encode", "format")):
        return "Serialization"
    return "Propagation"


def infer_sink_role(sink_category):
    roles = {
        "NETWORK": "Network transmission",
        "SMS_MMS": "Message transmission",
        "PHONE_CONNECTION": "Phone communication",
        "EMAIL": "Email transmission",
        "VOIP": "Voice transmission",
        "BLUETOOTH": "Bluetooth transmission",
        "IPC": "Inter-app communication",
        "FILE": "Local file storage",
        "DATABASE": "Local database storage",
        "SYNCHRONIZATION_DATA": "Synchronized storage",
        "LOG": "Logging",
    }
    return roles.get(sink_category or "", "Data exposure")


def infer_permission(source_category):
    permissions = {
        "LOCATION_INFORMATION": "ACCESS_FINE_LOCATION or ACCESS_COARSE_LOCATION",
        "CONTACT_INFORMATION": "READ_CONTACTS",
        "CALENDAR_INFORMATION": "READ_CALENDAR",
        "PHONE_CONNECTION": "READ_PHONE_STATE or CALL_PHONE",
        "SMS_MMS": "READ_SMS or SEND_SMS",
        "ACCOUNT_INFORMATION": "GET_ACCOUNTS",
        "UNIQUE_IDENTIFIER": "READ_PHONE_STATE or device identifier access",
    }
    return permissions.get(source_category or "", "Not available from FlowDroid output")


def is_third_party_signature(signature):
    text = (signature or "").lower()
    third_party_markers = [
        "analytics", "ads", "advert", "firebase", "crashlytics", "facebook",
        "flurry", "adjust", "appsflyer", "amplitude", "mixpanel", "segment",
        "bugsnag", "sentry", "branch", "kochava"
    ]
    return any(marker in text for marker in third_party_markers)


def protection_adjustments(*values):
    text = " ".join(value or "" for value in values).lower()
    return {
        "encryption": -2 if any(token in text for token in ("encrypt", "cipher", "aes", "rsa")) else 0,
        "secure_protocol": -1 if any(token in text for token in ("https", "ssl", "tls")) else 0,
        "anonymization": -1 if any(token in text for token in ("anonym", "pseudonym", "hash", "digest")) else 0,
    }


def risk_interpretation(source_category, sink_category, is_third_party):
    source_label = (source_category or "sensitive data").replace("_", " ").lower()
    sink_label = (sink_category or "an output sink").replace("_", " ").lower()
    if is_third_party:
        return f"{source_label.title()} may be shared with a third-party SDK or service."
    if sink_category in ["NETWORK", "SMS_MMS", "PHONE_CONNECTION", "EMAIL", "VOIP", "BLUETOOTH", "IPC"]:
        return f"{source_label.title()} may leave the app through {sink_label}."
    if sink_category in ["FILE", "DATABASE", "SYNCHRONIZATION_DATA"]:
        return f"{source_label.title()} may be persisted locally through {sink_label}."
    return f"{source_label.title()} reaches {sink_label}."


def risk_recommendation(level):
    actions = {
        "R1": "Consider data minimization and verify the collection is necessary.",
        "R2": "Ensure user consent and privacy-policy transparency.",
        "R3": "Apply secure storage mechanisms and access controls.",
        "R4": "Ensure secure transmission and disclose the data use.",
        "R5": "Review third-party sharing and document compliance obligations.",
        "R6": "Prioritize an immediate privacy audit and mitigation plan.",
    }
    return actions.get(level, "Review this flow before release.")
    
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

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        category = response.choices[0].message.content.strip()
    except Exception as exc:
        print(f"Sink classification unavailable: {exc}")
        return "UNKNOWN"
    
    # save to cache
    cache[clean] = category
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)
    
    return category
    
    
def calculate_risk(source, sink, leak_count):
    scores = {
        "sensitive_source": 0,
        "local_storage": 0,
        "network": 0,
        "third_party": 0,
        "multiple_sinks": 0,
        "encryption": 0,
        "secure_protocol": 0,
        "anonymization": 0
    }
    
    source_clean = clean_signature(source)
    sink_clean = clean_signature(sink)

     # look up source category
    source_category = SUSI["sources"].get(source_clean, None)
    if source_category and source_category != "NO_CATEGORY":
        scores["sensitive_source"] = 3
    permission = infer_permission(source_category)

    # look up sink category
    sink_category = SUSI["sinks"].get(sink_clean, None)
    third_party = is_third_party_signature(sink_clean)
    if third_party and not sink_category:
        sink_category = "THIRD_PARTY"

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
    if third_party:
        scores["third_party"] = 4
        if scores["network"] == 0:
            scores["network"] = 3

    # multiple sinks from same source
    if leak_count > 1:
        scores["multiple_sinks"] = 2
    scores.update(protection_adjustments(source_clean, sink_clean))

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
        "permission": permission,
        "level": level,
        "label": label,
        "interpretation": risk_interpretation(source_category, sink_category, third_party),
        "recommended_action": risk_recommendation(level)
    }
    
def run(
    apk_path,
    original_filename=None,
    timeout_seconds=None,
    write_report=True,
    stage_callback=None,
):
    app_name = original_filename or os.path.basename(apk_path)
    print(f"Analyzing {app_name}...")
    
    if stage_callback:
        stage_callback("running_flowdroid")
    output, analysis_mode = analyze_apk(apk_path, timeout_seconds=timeout_seconds)
    print(output[:500])
    if stage_callback:
        stage_callback("parsing")
    report = parse_output(output)
    report["app"] = app_name
    report["analysis_mode"] = analysis_mode
    if report.get("leak_count", 0) == 0:
        report["analysis_note"] = (
            "No configured FlowDroid source-to-sink leaks were detected. "
            "This is an absence of findings, not a proof that the APK is safe."
        )
    if analysis_mode in ("fallback_no_callbacks", "component_no_callbacks"):
        report["analysis_note"] = (
            "FlowDroid default callback analysis failed, so ExplainDroid retried "
            "with callbacks disabled. Results may miss flows that depend on "
            "Android callback entry points."
        )
    elif analysis_mode == "partial_component_fallback":
        report["analysis_note"] = (
            "FlowDroid default analysis failed, so ExplainDroid retried one "
            "component at a time with callbacks disabled. FlowDroid still failed "
            "before every component completed, so this is a partial report."
        )
    if stage_callback:
        stage_callback("summarizing")
    report["summary"] = summarize_with_llm(report)
    
    if write_report:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(REPORTS_DIR, f"{app_name}.json")
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {output_path}")
    
    print(f"Done! Found {report['leak_count']} leaks")
    return report

if __name__ == "__main__":
    run(sys.argv[1])
