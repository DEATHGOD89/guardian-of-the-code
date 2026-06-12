import yaml
import itertools
import os

def generate_rules():
    dangerous_functions = ["eval", "exec", "system", "popen", "shell_exec"]
    languages = ["python", "javascript", "php", "ruby"]

    rules = []
    for func, lang in itertools.product(dangerous_functions, languages):
        rules.append({
            "id": f"GEN_{lang.upper()}_{func.upper()}",
            "name": f"Dangerous function {func} called",
            "severity": "HIGH",
            "languages": [lang],
            "patterns": [{"regex": f"\\b{func}\\s*\\("}]
        })
        
    # Ensure rules directory exists
    os.makedirs("rules", exist_ok=True)
    
    with open("rules/generated_dangerous.yaml", "w") as f:
        yaml.dump({"rules": rules}, f)
        
    print(f"Successfully generated {len(rules)} rules into rules/generated_dangerous.yaml")

if __name__ == "__main__":
    generate_rules()
