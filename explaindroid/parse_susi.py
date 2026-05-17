import os 
import re
import json

def parse_susi_file(filepath):
    dictionary = {}
    current_category = None
    
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            
            # check if line is a category header
            if line.endswith(":") and not line.startswith("<"):
                current_category = line[:-1]
            
            # check if line is a method signature
            elif line.startswith("<"):
                # extract signature between < and >
                match = re.search(r"<(.*?)>", line)
                if match:
                    signature = match.group(1)
                    dictionary[signature] = current_category
    
    return dictionary


def build_susi_dictionaries(sources_file, sinks_file):
    sources = parse_susi_file(sources_file)
    sinks = parse_susi_file(sinks_file)
    
    combined = {
        "sources": sources,
        "sinks": sinks
    }
    
    with open("susi_dictionary.json", "w") as f:
        json.dump(combined, f, indent=2)
    
    print(f"Sources: {len(sources)} methods mapped")
    print(f"Sinks: {len(sinks)} methods mapped")
    print("Saved to susi_dictionary.json")

build_susi_dictionaries(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../FlowDroid/Ouput_CatSources_v0_9.txt")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../FlowDroid/Ouput_CatSinks_v0_9.txt"))
)
