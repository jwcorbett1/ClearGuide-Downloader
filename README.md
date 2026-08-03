# ClearGuide-Downloader
Python script to log into ClearGuide traffic data website and download *.csv files for specific, pre-built routes.

This script simplifies a recurring task which supports NCDOT in meeting the new FHWA work zone reporting requirements.  ClearGuide is a separate, subscription website which stores historic traffic data collected for most roadways in several states, including North Carolina.  Downloading data for all of the tracked work zones and setting the correct metrics to pull would take several hours to complete manually.

This script uses the OAuth 2.0 process to log into the ClearGuide website with the provided credentials on behalf of the user, download each pre-built work zone route, request the correct reporting metrics for each route as it is downloaded, and then package everything into a newly created folder named with the target date range.  The downloaded data is used to update a PowerBI dashboard (not included here) which NCDOT uses in meeting the FHWA requirements.
