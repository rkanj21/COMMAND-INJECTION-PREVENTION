import re
import nltk
from nltk import pos_tag, word_tokenize

# Ensure required NLTK packages are downloaded
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')

# List of potentially dangerous shell commands
DANGEROUS_COMMANDS = [
    'ls', 'cat', 'cd', 'rm', 'mkdir', 'cp', 'mv', 'touch', 'chmod', 'chown',
    'grep', 'find', 'echo', 'wget', 'curl', 'python', 'python3', 'bash', 'sh',
    'sudo', 'apt', 'apt-get', 'yum', 'brew', 'tar', 'zip', 'unzip', 'ping',
    'ssh', 'netstat', 'ifconfig', 'iptables', 'crontab', 'nc', 'nmap',
    'ps', 'kill', 'exec', 'eval', 'source', 'alias', 'export', 'env',
    'systemctl', 'service', 'shutdown', 'reboot', 'passwd'
]

# List of dangerous shell operators and symbols
DANGEROUS_OPERATORS = [
    ';', '&', '&&', '|', '||', '>', '>>', '<', '<<', '`', '$(',
    '$()', '${', '}', '$({})', '*', '?', '[', ']', '{}'
]

def detect_command_injection(input_string):
    """
    Detects potential command injection attempts using POS tagging and pattern matching.
    
    Args:
        input_string: The user input string to check
        
    Returns:
        bool: True if potential command injection is detected, False otherwise
    """
    if input_string is None or input_string.strip() == '':
        return False
    
    # Basic pattern matching for dangerous shell operators
    for operator in DANGEROUS_OPERATORS:
        if operator in input_string:
            return True
    
    # Tokenize input and perform POS tagging
    tokens = word_tokenize(input_string)
    pos_tags = pos_tag(tokens)
    
    # Check for sequence patterns that could indicate command injection
    # Look for commands followed by arguments (typical command pattern)
    for i, (word, tag) in enumerate(pos_tags):
        # Check if the word is a known dangerous command
        if word.lower() in DANGEROUS_COMMANDS:
            # If it's at the start or after a shell operator, it's suspicious
            if i == 0 or tokens[i-1] in ['&&', '||', ';', '|']:
                return True
            # If the command is tagged as a noun (NN) and followed by parameters
            if tag.startswith('NN') and i < len(pos_tags) - 1:
                next_word, next_tag = pos_tags[i+1]
                # If next word is a file path pattern or flag (-f, etc.)
                if next_tag in ['NN', 'NNS', 'JJ'] or next_word.startswith('-'):
                    return True
    
    # Check for pipe sequences: command | command
    for i in range(len(tokens) - 2):
        if tokens[i].lower() in DANGEROUS_COMMANDS and tokens[i+1] == '|' and tokens[i+2].lower() in DANGEROUS_COMMANDS:
            return True
    
    # Additional check for backtick execution syntax
    if re.search(r'`.*`', input_string):
        return True
    
    # Check for special bash variable syntax
    if re.search(r'\$\w+', input_string):
        return True
    
    # Advanced pattern: look for verb followed by file pattern
    for i, (word, tag) in enumerate(pos_tags):
        if tag.startswith('VB') and i < len(pos_tags) - 1:
            next_word, next_tag = pos_tags[i+1]
            # If looks like a file path after a verb
            if '/' in next_word or '.' in next_word:
                return True
    
    return False