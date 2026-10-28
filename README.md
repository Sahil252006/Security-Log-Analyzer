# Security Log Analyzer

## Project Overview

Security Log Analyzer is a Python-based web application developed for the subject Information Systems Security. It analyzes security log records, identifies repeated failed login attempts, displays interactive charts, and generates downloadable reports.

## Technologies Used

- Python
- Streamlit
- Pandas
- Plotly
- Git and GitHub

## Features

- Interactive security dashboard
- Sample security log dataset
- CSV file upload
- Detection of repeated failed login attempts
- Configurable detection threshold and time window
- IP address search
- Security event visualization
- Downloadable analyzed logs
- Downloadable security alert reports

## Project Structure

```text
Security-Log-Analyzer/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── data/
    └── sample_security_logs.csv
```

## How to Run Locally

1. Install Python.
2. Open the project folder in VS Code.
3. Create and activate a virtual environment.
4. Install the dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

5. Start the application:

   ```bash
   python -m streamlit run app.py
   ```

6. Open the local URL provided by Streamlit.

## Detection Method

The application examines login events marked as failed. It groups these events by IP address and checks whether the number of failures reaches the configured threshold within the selected time window.

## Limitations

This project analyzes the records provided by the user. Its alerts identify potentially suspicious patterns and do not independently establish that an attack has occurred.

The sample dataset is for demonstration purposes only.

## Future Enhancements

- Additional security detection rules
- More log file formats
- Improved reporting
- Historical trend analysis
- Authentication and access control

## Academic Purpose

Developed as an Information Systems Security project to demonstrate Python-based security log analysis and visualization.