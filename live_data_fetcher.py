import requests
from bs4 import BeautifulSoup
import sqlite3
import json
from datetime import datetime
import logging
from typing import List, Dict, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to fetch data from VirusTotal API
def fetch_virustotal_data(api_key: str, ioc: str) -> Union[Dict, None]:
    """Fetch live data from VirusTotal API for a given IOC."""
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from VirusTotal API: {e}")
        return None

# Function to scrape threat intelligence blogs
def scrape_threat_blog():
    """Scrape threat intelligence data from a user-provided blog or website."""
    url = input("Enter the URL of the threat intelligence blog: ")
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        articles = soup.find_all("article")
        return [article.text.strip() for article in articles]
    except requests.exceptions.RequestException as e:
        logging.error(f"Error scraping blog data: {e}")
        return None

# Function to fetch recent threat reports from the database
def fetch_recent_threat_reports(db_path):
    """Fetch recent threat reports from the local database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM threat_reports ORDER BY report_date DESC LIMIT 10"
    cursor.execute(query)
    reports = cursor.fetchall()
    conn.close()
    return reports

# Function to combine data from multiple sources
def get_combined_data(api_key, ioc, blog_url, db_path):
    """Aggregate data from API, web scraping, and database."""
    api_data = fetch_virustotal_data(api_key, ioc)
    blog_data = scrape_threat_blog(blog_url)
    db_data = fetch_recent_threat_reports(db_path)
    return {
        "api_data": api_data,
        "blog_data": blog_data,
        "db_data": db_data
    }

# Example usage
def main():
    api_key = "9d14ebf0f380f6ee50dbd7cbb18c01305d88818f22925dca1b39e81ea8313b36"
    ioc = "203.0.113.25"  # Example IOC
    blog_url = "https://example.com/threat-intelligence"
    db_path = "data/cybershield.db"

    combined_data = get_combined_data(api_key, ioc, blog_url, db_path)

    # Save combined data to a JSON file
    with open("live_data_output.json", "w") as file:
        json.dump(combined_data, file, indent=2)

    print("Live data fetched and saved successfully.")

if __name__ == "__main__":
    main()