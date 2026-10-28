# Subdomain Live Checker

A desktop application for checking subdomains, inspecting HTTP responses, tracking scan history, and exporting results.

## Features

- Check subdomains and inspect HTTP response status codes.
- Filter and review scan results.
- Track changes between scans using local scan history.
- Export results to CSV and HTML.
- Handle scan-history errors without incorrectly marking every result as new.
- Graphical interface built with Python and PySide6.

## Requirements

- Python 3.11 or a version supported by the project dependencies.
- Windows for the currently tested standalone executable.
- Internet access for checking remote hosts.

## Getting Started

### Run from source

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies and start the application:

```powershell
python -m pip install -r requirements.txt
python app.py
```

### Run the Windows executable

Download `SubdomainLiveChecker.exe` from GitHub Releases when a release is available, then run it on Windows.

The executable is built with PyInstaller. Linux and macOS builds have not been tested.

## Testing

Run the test suite:

```powershell
python -m pytest -q
python -m ruff check .
```

## Exports and Scan History

The application exports results to CSV and HTML and stores scan history locally.

Export performance has been stress-tested with 100,000 synthetic results. This does not represent 100,000 live network checks.

## Responsible Use

Only check systems and domains that you own or are explicitly authorized to assess. Respect applicable laws, service terms, rate limits, and network policies.

A failed HTTP check does not necessarily mean a subdomain does not exist. DNS issues, timeouts, network failures, redirects, and server configuration can affect results.

## Current Limitations

- The standalone executable has been tested on Windows only.
- Linux and macOS compatibility have not been verified.
- Network results depend on DNS, connectivity, timeouts, and remote server behavior.

## Contributing

Bug reports, feature suggestions, documentation improvements, and pull requests are welcome.

When reporting a bug, include reproduction steps, expected behavior, and actual behavior. Do not include secrets or sensitive scan data.

## License

See [LICENSE](LICENSE) for license details.
