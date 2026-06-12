import os
import yaml

# Read config for extensions and default ignores
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.yaml')
DEFAULT_ALLOWED_EXTENSIONS = ['.py', '.js', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.html', '.sql', '.ts', '.yaml', '.yml', '.json']
DEFAULT_IGNORE_DIRS = ['.git', 'node_modules', 'venv', '__pycache__', '.env', 'vendor']

allowed_extensions = DEFAULT_ALLOWED_EXTENSIONS
global_ignore_dirs = DEFAULT_IGNORE_DIRS

if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
            if config:
                if 'extensions' in config:
                    allowed_extensions = config['extensions']
                if 'ignore_dirs' in config:
                    global_ignore_dirs.extend(config['ignore_dirs'])
    except Exception:
        pass

def get_files(root_path, custom_ignore_dirs=None):
    ignore_dirs = set(global_ignore_dirs)
    if custom_ignore_dirs:
        ignore_dirs.update(custom_ignore_dirs)
        
    if os.path.isfile(root_path):
        yield root_path
        return

    for root, dirs, files in os.walk(root_path):
        # Modify dirs in place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            # If extensions is empty or * is present, allow all, else check
            if not allowed_extensions or '*' in allowed_extensions or ext in allowed_extensions:
                yield os.path.join(root, file)
