import yaml, glob, os

def load_rules(rules_dir):
    all_rules = []
    for yaml_file in glob.glob(os.path.join(rules_dir, '*.yaml')):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
            all_rules.extend(data.get('rules', []))
    return all_rules