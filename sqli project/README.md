# Command Injection Prevention System using POS Tagging

This project demonstrates how to use Natural Language Processing (NLP) with Part-of-Speech (POS) tagging to detect and prevent command injection attacks. The application is built with Flask and NLTK.

## Key Features

- **POS Tagging Detection**: Uses NLTK to analyze input text structure for command patterns
- **Pattern Recognition**: Identifies dangerous shell commands and operators
- **Syntactic Analysis**: Examines word relationships to detect potential command sequences
- **Secure Input Handling**: All user inputs are validated before processing

## Setup Instructions

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
4. Open your browser and navigate to `http://localhost:5000`

## How It Works

The system uses the following techniques to detect command injection attempts:

1. **Tokenization**: Breaks user input into individual tokens
2. **POS Tagging**: Labels each token with its part of speech (noun, verb, etc.)
3. **Pattern Analysis**: Looks for patterns common in command injections:
   - Commands followed by arguments
   - Shell operators (`&&`, `||`, `;`, etc.)
   - Command piping (`|`)
   - Backtick execution (`` `command` ``)
   - Environment variables (`$VAR`)

## Project Structure

- `app.py`: Main Flask application
- `command_injection_detector.py`: Core logic for command injection detection using NLP
- `schema.sql`: Database schema
- `templates/`: HTML templates for the application
- `requirements.txt`: Python dependencies

## Testing Command Injection Prevention

The application provides several entry points to test the command injection detection:

- Login form
- Registration form
- Search functionality
- Post creation

Try entering various command injection patterns such as:
- `username; ls -la`
- `password && cat /etc/passwd`
- `search term || rm -rf /`

The system should detect these patterns and prevent the injection.

## Default Credentials

Two users are created by default for testing:
- Username: `admin`, Password: `admin`
- Username: `user`, Password: `user`

## License

This project is for educational purposes only.

## Contributing

Feel free to contribute to this project by opening issues or submitting pull requests.