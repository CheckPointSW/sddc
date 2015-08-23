# Overview

Tools for integration with the Software Defined Data Center (SDDC).


# Monitor

The monitor.py script can be used to poll AWS and OpenStack controllers and
create/delete matching gateway objects in Check Point R80 SmartCenter server.

## Configuration:
The configuration is defined in a JSON file (e.g., `conf.json`), the format is
described at the bottom of monitor.py.

## Running:
	./monitor.py --port 80 @conf.json

The script will start a web server on port 80 where a simple status page can be
viewed with a web browser.
