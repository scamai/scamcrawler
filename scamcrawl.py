import requests
from bs4 import BeautifulSoup
import re
import whois
import dns.resolver
import time
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime
from typing import List, Dict, Set, Optional
import tld
from fake_useragent import UserAgent
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

class MongoIntelCrawler:
    def __init__(self, mongo_uri: str, database: str):
        """
        Initialize the crawler with MongoDB configuration
        """
        self.client = MongoClient(mongo_uri)
        self.db: Database = self.client[database]
        self.scam_data: Collection = self.db.scam_data
        self.domains: Collection = self.db.domains
        self.visited_urls: Set[str] = set()
        self.ua = UserAgent()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=f'crawler_{datetime.now().strftime("%Y%m%d")}.log'
        )
        
        # Patterns for identifying sensitive information
        self.patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}',
            'crypto_wallet': {
                'bitcoin': r'bc1[a-zA-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
                'ethereum': r'0x[a-fA-F0-9]{40}',
                'litecoin': r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}',
                'ripple': r'r[0-9a-zA-Z]{24,34}',
            },
            'social_media': {
                'facebook': r'facebook\.com/[\w\.]+',
                'twitter': r'twitter\.com/[\w]+',
                'instagram': r'instagram\.com/[\w\.]+',
                'telegram': r't\.me/[\w]+',
                'discord': r'discord\.gg/[\w]+',
            }
        }

    def get_domain_info(self, url: str) -> Dict:
        """
        Gather domain information using WHOIS and DNS
        """
        try:
            domain = tld.get_fld(url)
            w = whois.whois(domain)
            
            dns_info = {
                'A': [],
                'MX': [],
                'NS': [],
                'TXT': []
            }
            
            for record_type in dns_info.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(answer) for answer in answers]
                except:
                    continue
                    
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'last_updated': w.updated_date,
                'status': w.status,
                'name_servers': w.name_servers,
                'dns_records': dns_info,
                'first_seen': datetime.now(),
                'last_checked': datetime.now()
            }
        except Exception as e:
            logging.error(f"Error getting domain info for {url}: {str(e)}")
            return {}

    def is_suspicious_domain(self, domain_info: Dict) -> bool:
        """
        Evaluate domain for suspicious characteristics
        """
        if not domain_info:
            return False
            
        suspicious_factors = 0
        
        # Check domain age
        if domain_info.get('creation_date'):
            creation_date = domain_info['creation_date']
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
            if domain_age < 30:
                suspicious_factors += 2
                
        # Check for missing DNS records
        dns_records = domain_info.get('dns_records', {})
        if not dns_records.get('MX'):
            suspicious_factors += 1
            
        return suspicious_factors >= 2

    def extract_information(self, url: str, html_content: str) -> Dict:
        """
        Extract relevant information from webpage content
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        extracted_data = {
            'url': url,
            'title': soup.title.string if soup.title else None,
            'emails': set(),
            'phones': set(),
            'crypto_wallets': [],
            'social_media': [],
            'text_content': soup.get_text(),
            'links': [],
            'timestamp': datetime.now()
        }
        
        # Extract information using patterns
        for pattern_type, pattern in self.patterns.items():
            if isinstance(pattern, dict):
                for sub_type, sub_pattern in pattern.items():
                    matches = re.finditer(sub_pattern, html_content, re.IGNORECASE)
                    for match in matches:
                        if pattern_type == 'crypto_wallets':
                            extracted_data['crypto_wallets'].append({
                                'type': sub_type,
                                'address': match.group()
                            })
                        elif pattern_type == 'social_media':
                            extracted_data['social_media'].append({
                                'platform': sub_type,
                                'profile': match.group()
                            })
            else:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)
                extracted_data[pattern_type].update(match.group() for match in matches)
        
        # Convert sets to lists for MongoDB storage
        extracted_data['emails'] = list(extracted_data['emails'])
        extracted_data['phones'] = list(extracted_data['phones'])
        
        return extracted_data

    def store_data(self, data: Dict) -> None:
        """
        Store extracted data in MongoDB
        """
        try:
            # Store domain information
            domain_info = self.get_domain_info(data['url'])
            if domain_info:
                self.domains.update_one(
                    {'domain': domain_info['domain']},
                    {'$set': domain_info},
                    upsert=True
                )
            
            # Store scam data
            self.scam_data.insert_one({
                'url': data['url'],
                'title': data['title'],
                'emails': data['emails'],
                'phones': data['phones'],
                'crypto_wallets': data['crypto_wallets'],
                'social_media': data['social_media'],
                'domain_info': domain_info,
                'timestamp': data['timestamp'],
                'suspicious_score': 2 if self.is_suspicious_domain(domain_info) else 1
            })
            
        except Exception as e:
            logging.error(f"Database error: {str(e)}")

    def crawl_url(self, url: str, depth: int = 0, max_depth: int = 3) -> None:
        """
        Crawl a URL and its linked pages up to max_depth
        """
        if depth > max_depth or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            headers = {'User-Agent': self.ua.random}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Extract and store information
            extracted_data = self.extract_information(url, response.text)
            if any(len(v) > 0 for v in [extracted_data['emails'], extracted_data['phones'], 
                                      extracted_data['crypto_wallets'], extracted_data['social_media']]):
                self.store_data(extracted_data)
                
            # Find and crawl linked pages
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                next_url = urljoin(url, link['href'])
                if next_url.startswith('http'):
                    self.crawl_url(next_url, depth + 1, max_depth)
                    
        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")

    def start_crawling(self, seed_urls: List[str], max_workers: int = 5) -> None:
        """
        Start crawling from a list of seed URLs using multiple threads
        """
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.crawl_url, seed_urls)

# Example usage
if __name__ == "__main__":
    mongo_config = {
        'uri': 'mongodb://localhost:27017/',
        'database': 'scam_intelligence'
    }
    
    seed_urls = [
        # Add your seed URLs here
    ]
    
    crawler = MongoIntelCrawler(mongo_config['uri'], mongo_config['database'])
    crawler.start_crawling(seed_urls)