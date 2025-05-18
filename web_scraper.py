import trafilatura
import streamlit as st
import json
import re
import datetime
from data_processing import save_processed_data

def get_website_text_content(url: str) -> str | None:
    """
    Extract the main text content of a website using trafilatura.
    
    Args:
        url: The URL of the website to scrape
        
    Returns:
        The extracted text content or None if extraction fails
    """
    try:
        # Download the content from the URL
        downloaded = trafilatura.fetch_url(url)
        
        if downloaded is None:
            return None
            
        # Extract the main text content
        text = trafilatura.extract(downloaded)
        
        if text is None:
            return ""
            
        return text
    except Exception as e:
        st.error(f"Error extracting content from {url}: {str(e)}")
        return None

def process_website_content(url: str, nlp, extract_iocs_func, extract_ttps_func):
    """
    Process website content to extract threat intelligence.
    
    Args:
        url: The URL of the website to scrape
        nlp: The NLP model to use for extraction
        extract_iocs_func: Function to extract IOCs
        extract_ttps_func: Function to extract TTPs
        
    Returns:
        Dictionary containing extracted threat intelligence
    """
    # Extract text content from the website
    text_content = get_website_text_content(url)
    
    if not text_content:
        return None
    
    # Extract IOCs and TTPs using the provided functions
    iocs = extract_iocs_func(text_content, nlp)
    ttps = extract_ttps_func(text_content)
    
    # Create result
    result = {
        "report_type": "web",
        "source_url": url,
        "extraction_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "extracted_iocs": iocs,
        "extracted_ttps": ttps,
        "text_content": text_content[:1000] + "..." if len(text_content) > 1000 else text_content
    }
    
    return result
    
def save_website_report(result, filename=None):
    """
    Save the extracted website content and intelligence to a file.
    
    Args:
        result: Dictionary containing extracted threat intelligence
        filename: Optional filename for the saved report
        
    Returns:
        Path to the saved file
    """
    if filename is None:
        source_domain = re.search(r'https?://(?:www\.)?([^/]+)', result["source_url"])
        if source_domain:
            domain = source_domain.group(1).replace('.', '_')
            filename = f"web_threat_report_{domain}_{datetime.datetime.now().strftime('%Y%m%d')}.json"
        else:
            filename = f"web_threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    return save_processed_data(result, filename)

def extract_urls_from_text(text):
    """
    Extract URLs from text content.
    
    Args:
        text: Text content to extract URLs from
        
    Returns:
        List of extracted URLs
    """
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates